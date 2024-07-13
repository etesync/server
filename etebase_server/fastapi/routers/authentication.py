import random
import typing as t
from datetime import datetime

import nacl
import nacl.encoding
import nacl.hash
import nacl.secret
import nacl.signing
from django.conf import settings
from django.contrib.auth import user_logged_in, user_logged_out
from django.core import exceptions as django_exceptions
from django.db import transaction
from django.utils.functional import cached_property
from fastapi import APIRouter, Depends, Request, status
from typing_extensions import Literal

from etebase_server.django import app_settings, models
from etebase_server.django.models import UserInfo
from etebase_server.django.signals import user_signed_up
from etebase_server.django.token_auth.models import AuthToken
from etebase_server.django.utils import CallbackContext, create_user, get_user_queryset
from etebase_server.myauth.models import UserType, get_typed_user_model

from ..dependencies import AuthData, get_auth_data, get_authenticated_user
from ..exceptions import AuthenticationFailed, HttpError, transform_validation_error
from ..msgpack import MsgpackResponse, MsgpackRoute
from ..utils import BaseModel, get_user_username_email_kwargs, msgpack_decode, msgpack_encode, permission_responses

User = get_typed_user_model()
authentication_router = APIRouter(route_class=MsgpackRoute)


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
    action: Literal["login", "changePassword"]


class UserOut(BaseModel):
    username: str
    email: str
    pubkey: bytes
    encryptedContent: bytes

    @classmethod
    def from_orm(cls: t.Type["UserOut"], obj: UserType) -> "UserOut":
        return cls(
            username=obj.username,
            email=obj.email,
            pubkey=bytes(obj.userinfo.pubkey),
            encryptedContent=bytes(obj.userinfo.encryptedContent),
        )


class LoginOut(BaseModel):
    token: str
    user: UserOut

    @classmethod
    def from_orm(cls: t.Type["LoginOut"], obj: UserType) -> "LoginOut":
        token = AuthToken.objects.create(user=obj).key
        user = UserOut.from_orm(obj)
        return cls(token=token, user=user)


class Authentication(BaseModel):
    class Config:
        ignored_types = (cached_property,)

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


def get_login_user(request: Request, challenge: LoginChallengeIn) -> UserType:
    username = challenge.username

    kwargs = get_user_username_email_kwargs(username)
    try:
        user_queryset = get_user_queryset(User.objects.all(), CallbackContext(request.path_params))
        user = user_queryset.get(**kwargs)
        if not hasattr(user, "userinfo"):
            raise AuthenticationFailed(code="user_not_init", detail="User not properly init")
        return user
    except User.DoesNotExist:
        return fake_user(username)


FAKE_USER_COUNT = 1000


def fake_user(username: str) -> UserType:
    username_bytes = bytes(username, encoding="utf-8")
    login_pubkey = get_encryption_key(b"", b"loginPubkey", username_bytes)[:32]
    salt = get_encryption_key(b"", b"salt", username_bytes)[:16]

    user = User()
    user.username = username
    user.id = random.Random(settings.SECRET_KEY + username).randint(0, FAKE_USER_COUNT)

    userinfo = UserInfo()
    userinfo.loginPubkey = login_pubkey
    userinfo.salt = salt

    user.userinfo = userinfo
    return user


def get_encryption_key(salt: bytes, person=b"etebase-auth", data: bytes = b""):
    key = nacl.hash.blake2b(settings.SECRET_KEY.encode(), encoder=nacl.encoding.RawEncoder)
    return nacl.hash.blake2b(
        data=data,
        key=key,
        salt=salt[: nacl.hash.BLAKE2B_SALTBYTES],
        person=person,
        encoder=nacl.encoding.RawEncoder,
    )


def save_changed_password(data: ChangePassword, user: UserType):
    response_data = data.response_data
    user_info: UserInfo = user.userinfo
    user_info.loginPubkey = response_data.loginPubkey
    user_info.encryptedContent = response_data.encryptedContent
    user_info.save()


def validate_login_request(
    validated_data: LoginResponse,
    challenge_sent_to_user: Authentication,
    user: UserType,
    expected_action: str,
    host_from_request: str,
):
    enc_key = get_encryption_key(bytes(user.userinfo.salt))
    box = nacl.secret.SecretBox(enc_key)
    challenge_data = msgpack_decode(box.decrypt(validated_data.challenge))
    now = int(datetime.now().timestamp())
    if validated_data.action != expected_action:
        raise HttpError("wrong_action", f'Expected "{expected_action}" but got something else')
    elif now - challenge_data["timestamp"] > app_settings.CHALLENGE_VALID_SECONDS:
        raise HttpError("challenge_expired", "Login challenge has expired")
    elif challenge_data["userId"] != user.id:
        raise HttpError("wrong_user", "This challenge is for the wrong user")
    elif not settings.DEBUG and validated_data.host.split(":", 1)[0] != host_from_request.split(":", 1)[0]:
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
def login_challenge(user: UserType = Depends(get_login_user)):
    salt = bytes(user.userinfo.salt)
    enc_key = get_encryption_key(salt)
    box = nacl.secret.SecretBox(enc_key)
    challenge_data = {
        "timestamp": int(datetime.now().timestamp()),
        "userId": user.id,
    }
    challenge = bytes(box.encrypt(msgpack_encode(challenge_data), encoder=nacl.encoding.RawEncoder))
    return MsgpackResponse(LoginChallengeOut(salt=salt, challenge=challenge, version=user.userinfo.version))


@authentication_router.post("/login/", response_model=LoginOut)
def login(data: Login, request: Request):
    user = get_login_user(request, LoginChallengeIn(username=data.response_data.username))
    host = request.headers.get("Host")
    validate_login_request(data.response_data, data, user, "login", host)
    ret = LoginOut.from_orm(user)
    user_logged_in.send(sender=user.__class__, request=None, user=user)
    return MsgpackResponse(ret)


@authentication_router.post("/logout/", status_code=status.HTTP_204_NO_CONTENT, responses=permission_responses)
def logout(auth_data: AuthData = Depends(get_auth_data)):
    auth_data.token.delete()
    user_logged_out.send(sender=auth_data.user.__class__, request=None, user=auth_data.user)


@authentication_router.post("/change_password/", status_code=status.HTTP_204_NO_CONTENT, responses=permission_responses)
def change_password(data: ChangePassword, request: Request, user: UserType = Depends(get_authenticated_user)):
    host = request.headers.get("Host")
    validate_login_request(data.response_data, data, user, "changePassword", host)
    save_changed_password(data, user)


@authentication_router.post("/dashboard_url/", responses=permission_responses)
def dashboard_url(request: Request, user: UserType = Depends(get_authenticated_user)):
    get_dashboard_url = app_settings.DASHBOARD_URL_FUNC
    if get_dashboard_url is None:
        raise HttpError("not_supported", "This server doesn't have a user dashboard.")

    ret = {
        "url": get_dashboard_url(CallbackContext(request.path_params, user=user)),
    }
    return MsgpackResponse(ret)


def signup_save(data: SignupIn, request: Request) -> UserType:
    user_data = data.user
    with transaction.atomic():
        try:
            user_queryset = get_user_queryset(User.objects.all(), CallbackContext(request.path_params))
            instance = user_queryset.get(**{User.USERNAME_FIELD: user_data.username.lower()})
        except User.DoesNotExist:
            # Create the user and save the casing the user chose as the first name
            try:
                instance = create_user(
                    CallbackContext(request.path_params),
                    **user_data.dict(),
                    password=None,
                    first_name=user_data.username,
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
    ret = LoginOut.from_orm(user)
    user_signed_up.send(sender=user.__class__, request=None, user=user)
    return MsgpackResponse(ret)
