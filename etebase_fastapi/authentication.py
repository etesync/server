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
from django.core import exceptions as django_exceptions
from django.db import transaction
from django.utils import timezone
from fastapi import APIRouter, Depends, status, Request
from fastapi.security import APIKeyHeader

from django_etebase import app_settings, models
from django_etebase.models import UserInfo
from django_etebase.signals import user_signed_up
from django_etebase.token_auth.models import AuthToken
from django_etebase.token_auth.models import get_default_expiry
from django_etebase.utils import create_user, get_user_queryset, CallbackContext
from .exceptions import AuthenticationFailed, transform_validation_error, HttpError
from .msgpack import MsgpackRoute
from .utils import BaseModel, permission_responses, msgpack_encode, msgpack_decode

User = get_user_model()
token_scheme = APIKeyHeader(name="Authorization")
AUTO_REFRESH = True
MIN_REFRESH_INTERVAL = 60
authentication_router = APIRouter(route_class=MsgpackRoute)


@dataclasses.dataclass(frozen=True)
class AuthData:
    user: User
    token: AuthToken


class LoginChallengeIn(BaseModel):
    username: str


class LoginChallengeOut(BaseModel):
    salt: bytes
    challenge: bytes
    version: int


class LoginResponse(BaseModel):
    username: str
    challenge: bytes
    host: str
    action: t.Literal["login", "changePassword"]


class UserOut(BaseModel):
    pubkey: bytes
    encryptedContent: bytes

    @classmethod
    def from_orm(cls: t.Type["UserOut"], obj: User) -> "UserOut":
        return cls(pubkey=bytes(obj.userinfo.pubkey), encryptedContent=bytes(obj.userinfo.encryptedContent))


class LoginOut(BaseModel):
    token: str
    user: UserOut

    @classmethod
    def from_orm(cls: t.Type["LoginOut"], obj: User) -> "LoginOut":
        token = AuthToken.objects.create(user=obj).key
        user = UserOut.from_orm(obj)
        return cls(token=token, user=user)


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


class UserSignup(BaseModel):
    username: str
    email: str


class SignupIn(BaseModel):
    user: UserSignup
    salt: bytes
    loginPubkey: bytes
    pubkey: bytes
    encryptedContent: bytes


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


async def get_login_user(challenge: LoginChallengeIn) -> User:
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


def save_changed_password(data: ChangePassword, user: User):
    response_data = data.response_data
    user_info: UserInfo = user.userinfo
    user_info.loginPubkey = response_data.loginPubkey
    user_info.encryptedContent = response_data.encryptedContent
    user_info.save()


@sync_to_async
def validate_login_request(
    validated_data: LoginResponse,
    challenge_sent_to_user: Authentication,
    user: User,
    expected_action: str,
    host_from_request: str,
):
    enc_key = get_encryption_key(bytes(user.userinfo.salt))
    box = nacl.secret.SecretBox(enc_key)
    challenge_data = msgpack_decode(box.decrypt(validated_data.challenge))
    now = int(datetime.now().timestamp())
    if validated_data.action != expected_action:
        raise HttpError("wrong_action", f'Expected "{challenge_sent_to_user.response}" but got something else')
    elif now - challenge_data["timestamp"] > app_settings.CHALLENGE_VALID_SECONDS:
        raise HttpError("challenge_expired", "Login challenge has expired")
    elif challenge_data["userId"] != user.id:
        raise HttpError("wrong_user", "This challenge is for the wrong user")
    elif not settings.DEBUG and validated_data.host.split(":", 1)[0] != host_from_request:
        raise HttpError(
            "wrong_host", f'Found wrong host name. Got: "{validated_data.host}" expected: "{host_from_request}"'
        )
    verify_key = nacl.signing.VerifyKey(bytes(user.userinfo.loginPubkey), encoder=nacl.encoding.RawEncoder)
    try:
        verify_key.verify(challenge_sent_to_user.response, challenge_sent_to_user.signature)
    except nacl.exceptions.BadSignatureError:
        raise HttpError("login_bad_signature", "Wrong password for user.", status.HTTP_401_UNAUTHORIZED)


@authentication_router.get("/is_etebase/")
async def is_etebase():
    pass


@authentication_router.post("/login_challenge/", response_model=LoginChallengeOut)
async def login_challenge(user: User = Depends(get_login_user)):
    salt = bytes(user.userinfo.salt)
    enc_key = get_encryption_key(salt)
    box = nacl.secret.SecretBox(enc_key)
    challenge_data = {
        "timestamp": int(datetime.now().timestamp()),
        "userId": user.id,
    }
    challenge = bytes(box.encrypt(msgpack_encode(challenge_data), encoder=nacl.encoding.RawEncoder))
    return LoginChallengeOut(salt=salt, challenge=challenge, version=user.userinfo.version)


@authentication_router.post("/login/", response_model=LoginOut)
async def login(data: Login, request: Request):
    user = await get_login_user(LoginChallengeIn(username=data.response_data.username))
    host = request.headers.get("Host")
    await validate_login_request(data.response_data, data, user, "login", host)
    data = await sync_to_async(LoginOut.from_orm)(user)
    await sync_to_async(user_logged_in.send)(sender=user.__class__, request=None, user=user)
    return data


@authentication_router.post("/logout/", status_code=status.HTTP_204_NO_CONTENT, responses=permission_responses)
def logout(request: Request, auth_data: AuthData = Depends(get_auth_data)):
    auth_data.token.delete()
    user_logged_out.send(sender=auth_data.user.__class__, request=None, user=auth_data.user)


@authentication_router.post("/change_password/", status_code=status.HTTP_204_NO_CONTENT, responses=permission_responses)
async def change_password(data: ChangePassword, request: Request, user: User = Depends(get_authenticated_user)):
    host = request.headers.get("Host")
    await validate_login_request(data.response_data, data, user, "changePassword", host)
    await sync_to_async(save_changed_password)(data, user)


@authentication_router.post("/dashboard_url/", responses=permission_responses)
def dashboard_url(request: Request, user: User = Depends(get_authenticated_user)):
    get_dashboard_url = app_settings.DASHBOARD_URL_FUNC
    if get_dashboard_url is None:
        raise HttpError("not_supported", "This server doesn't have a user dashboard.")

    ret = {
        "url": get_dashboard_url(CallbackContext(request.path_params, user=user)),
    }
    return ret


def signup_save(data: SignupIn, request: Request) -> User:
    user_data = data.user
    with transaction.atomic():
        try:
            user_queryset = get_user_queryset(User.objects.all(), CallbackContext(request.path_params))
            instance = user_queryset.get(**{User.USERNAME_FIELD: user_data.username.lower()})
        except User.DoesNotExist:
            # Create the user and save the casing the user chose as the first name
            try:
                instance = create_user(
                    **user_data.dict(),
                    password=None,
                    first_name=user_data.username,
                    context=CallbackContext(request.path_params),
                )
                instance.full_clean()
            except HttpError as e:
                raise e
            except django_exceptions.ValidationError as e:
                transform_validation_error("user", e)
            except Exception as e:
                raise HttpError("generic", str(e))

        if hasattr(instance, "userinfo"):
            raise HttpError("user_exists", "User already exists", status_code=status.HTTP_409_CONFLICT)

        models.UserInfo.objects.create(**data.dict(exclude={"user"}), owner=instance)
    return instance


@authentication_router.post("/signup/", response_model=LoginOut, status_code=status.HTTP_201_CREATED)
def signup(data: SignupIn, request: Request):
    user = signup_save(data, request)
    data = LoginOut.from_orm(user)
    user_signed_up.send(sender=user.__class__, request=None, user=user)
    return data
