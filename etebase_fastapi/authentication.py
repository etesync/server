import dataclasses
import typing as t
from datetime import datetime
from functools import cached_property

import nacl
import nacl.encoding
import nacl.hash
import nacl.secret
import nacl.signing
from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth import get_user_model, user_logged_out, user_logged_in
from django.utils import timezone
from fastapi import APIRouter, Depends, status, Request, Response
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from django_etebase import app_settings
from django_etebase.models import UserInfo
from django_etebase.serializers import UserSerializer
from django_etebase.token_auth.models import AuthToken
from django_etebase.token_auth.models import get_default_expiry
from django_etebase.views import msgpack_encode, msgpack_decode
from .execptions import AuthenticationFailed
from .msgpack import MsgpackResponse, MsgpackRoute

User = get_user_model()
token_scheme = APIKeyHeader(name="Authorization")
AUTO_REFRESH = True
MIN_REFRESH_INTERVAL = 60
authentication_router = APIRouter(route_class=MsgpackRoute)


@dataclasses.dataclass(frozen=True)
class AuthData:
    user: User
    token: AuthToken


class LoginChallengeData(BaseModel):
    username: str


class LoginResponse(BaseModel):
    username: str
    challenge: bytes
    host: str
    action: t.Literal["login", "changePassword"]


class Authentication(BaseModel):
    class Config:
        keep_untouched = (cached_property,)

    response: bytes
    signature: bytes


class Login(Authentication):
    @cached_property
    def response_data(self) -> LoginResponse:
        return LoginResponse(**msgpack_decode(self.response))


class ChangePasswordResponse(LoginResponse):
    loginPubkey: bytes
    encryptedContent: bytes


class ChangePassword(Authentication):
    @cached_property
    def response_data(self) -> ChangePasswordResponse:
        return ChangePasswordResponse(**msgpack_decode(self.response))


def __renew_token(auth_token: AuthToken):
    current_expiry = auth_token.expiry
    new_expiry = get_default_expiry()
    # Throttle refreshing of token to avoid db writes
    delta = (new_expiry - current_expiry).total_seconds()
    if delta > MIN_REFRESH_INTERVAL:
        auth_token.expiry = new_expiry
        auth_token.save(update_fields=("expiry",))


@sync_to_async
def __get_authenticated_user(api_token: str):
    api_token = api_token.split()[1]
    try:
        token: AuthToken = AuthToken.objects.select_related("user").get(key=api_token)
    except AuthToken.DoesNotExist:
        raise AuthenticationFailed(detail="Invalid token.")
    if not token.user.is_active:
        raise AuthenticationFailed(detail="User inactive or deleted.")

    if token.expiry is not None:
        if token.expiry < timezone.now():
            token.delete()
            raise AuthenticationFailed(detail="Invalid token.")

        if AUTO_REFRESH:
            __renew_token(token)

    return token.user, token


async def get_auth_data(api_token: str = Depends(token_scheme)) -> AuthData:
    user, token = await __get_authenticated_user(api_token)
    return AuthData(user, token)


async def get_authenticated_user(api_token: str = Depends(token_scheme)) -> User:
    user, token = await __get_authenticated_user(api_token)
    return user


@sync_to_async
def __get_login_user(username: str) -> User:
    kwargs = {User.USERNAME_FIELD + "__iexact": username.lower()}
    try:
        user = User.objects.get(**kwargs)
        if not hasattr(user, "userinfo"):
            raise AuthenticationFailed(code="user_not_init", detail="User not properly init")
        return user
    except User.DoesNotExist:
        raise AuthenticationFailed(code="user_not_found", detail="User not found")


async def get_login_user(challenge: LoginChallengeData) -> User:
    user = await __get_login_user(challenge.username)
    return user


def get_encryption_key(salt):
    key = nacl.hash.blake2b(settings.SECRET_KEY.encode(), encoder=nacl.encoding.RawEncoder)
    return nacl.hash.blake2b(
        b"",
        key=key,
        salt=salt[: nacl.hash.BLAKE2B_SALTBYTES],
        person=b"etebase-auth",
        encoder=nacl.encoding.RawEncoder,
    )


@sync_to_async
def save_changed_password(data: ChangePassword, user: User):
    response_data = data.response_data
    user_info: UserInfo = user.userinfo
    user_info.loginPubkey = response_data.loginPubkey
    user_info.encryptedContent = response_data.encryptedContent
    user_info.save()


@sync_to_async
def login_response_data(user: User):
    return {
        "token": AuthToken.objects.create(user=user).key,
        "user": UserSerializer(user).data,
    }


@sync_to_async
def send_user_logged_in_async(user: User, request: Request):
    user_logged_in.send(sender=user.__class__, request=request, user=user)


@sync_to_async
def send_user_logged_out_async(user: User, request: Request):
    user_logged_out.send(sender=user.__class__, request=request, user=user)


@sync_to_async
def validate_login_request(
    validated_data: LoginResponse,
    challenge_sent_to_user: Authentication,
    user: User,
    expected_action: str,
    host_from_request: str,
) -> t.Optional[MsgpackResponse]:

    enc_key = get_encryption_key(bytes(user.userinfo.salt))
    box = nacl.secret.SecretBox(enc_key)
    challenge_data = msgpack_decode(box.decrypt(validated_data.challenge))
    now = int(datetime.now().timestamp())
    if validated_data.action != expected_action:
        content = {
            "code": "wrong_action",
            "detail": 'Expected "{}" but got something else'.format(challenge_sent_to_user.response),
        }
        return MsgpackResponse(content, status_code=status.HTTP_400_BAD_REQUEST)
    elif now - challenge_data["timestamp"] > app_settings.CHALLENGE_VALID_SECONDS:
        content = {"code": "challenge_expired", "detail": "Login challenge has expired"}
        return MsgpackResponse(content, status_code=status.HTTP_400_BAD_REQUEST)
    elif challenge_data["userId"] != user.id:
        content = {"code": "wrong_user", "detail": "This challenge is for the wrong user"}
        return MsgpackResponse(content, status_code=status.HTTP_400_BAD_REQUEST)
    elif not settings.DEBUG and validated_data.host.split(":", 1)[0] != host_from_request:
        detail = 'Found wrong host name. Got: "{}" expected: "{}"'.format(validated_data.host, host_from_request)
        content = {"code": "wrong_host", "detail": detail}
        return MsgpackResponse(content, status_code=status.HTTP_400_BAD_REQUEST)

    verify_key = nacl.signing.VerifyKey(bytes(user.userinfo.loginPubkey), encoder=nacl.encoding.RawEncoder)

    try:
        verify_key.verify(challenge_sent_to_user.response, challenge_sent_to_user.signature)
    except nacl.exceptions.BadSignatureError:
        return MsgpackResponse(
            {"code": "login_bad_signature", "detail": "Wrong password for user."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    return None


@authentication_router.post("/login_challenge/")
async def login_challenge(user: User = Depends(get_login_user)):
    enc_key = get_encryption_key(user.userinfo.salt)
    box = nacl.secret.SecretBox(enc_key)
    challenge_data = {
        "timestamp": int(datetime.now().timestamp()),
        "userId": user.id,
    }
    challenge = bytes(box.encrypt(msgpack_encode(challenge_data), encoder=nacl.encoding.RawEncoder))
    return MsgpackResponse({"salt": user.userinfo.salt, "version": user.userinfo.version, "challenge": challenge})


@authentication_router.post("/login/")
async def login(data: Login, request: Request):
    user = await get_login_user(LoginChallengeData(username=data.response_data.username))
    host = request.headers.get("Host")
    bad_login_response = await validate_login_request(data.response_data, data, user, "login", host)
    if bad_login_response is not None:
        return bad_login_response
    data = await login_response_data(user)
    await send_user_logged_in_async(user, request)
    return MsgpackResponse(data, status_code=status.HTTP_200_OK)


@authentication_router.post("/logout/")
async def logout(request: Request, auth_data: AuthData = Depends(get_auth_data)):
    await sync_to_async(auth_data.token.delete)()
    await send_user_logged_out_async(auth_data.user, request)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@authentication_router.post("/change_password/")
async def change_password(data: ChangePassword, request: Request, user: User = Depends(get_authenticated_user)):
    host = request.headers.get("Host")
    bad_login_response = await validate_login_request(data.response_data, data, user, "changePassword", host)
    if bad_login_response is not None:
        return bad_login_response
    await save_changed_password(data, user)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
