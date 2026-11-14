"""Changing the password ends the user's other sessions, while the session that changed it keeps working."""

import nacl.signing
import pytest

from etebase_server.django import models
from etebase_server.django.token_auth.models import AuthToken
from etebase_server.fastapi.utils import msgpack_encode

NEW_LOGIN_PUBKEY = b"n" * 32
NEW_CONTENT = b"content encrypted with the new password"


@pytest.fixture
def signing_key(user):
    """Login key of ``user``, registered as its ``loginPubkey``."""
    key = nacl.signing.SigningKey.generate()
    models.UserInfo.objects.create(
        owner=user, loginPubkey=bytes(key.verify_key), pubkey=b"p" * 32, encryptedContent=b"old", salt=b"s" * 16
    )
    return key


def change_password(api_request, token, user, signing_key):
    status, challenge = api_request("POST", "/api/v1/authentication/login_challenge/", body={"username": user.username})
    assert status == 200
    response = msgpack_encode(
        {
            "username": user.username,
            "challenge": challenge["challenge"],
            "host": "testserver",
            "action": "changePassword",
            "loginPubkey": NEW_LOGIN_PUBKEY,
            "encryptedContent": NEW_CONTENT,
        }
    )
    body = {"response": response, "signature": signing_key.sign(response).signature}
    return api_request("POST", "/api/v1/authentication/change_password/", body=body, token=token)


def collection_list_status(api_request, token):
    return api_request("GET", "/api/v1/collection/", token=token)[0]


def test_password_change_ends_the_other_sessions(api_request, user, auth_token, signing_key, other_auth_token):
    token_of_other_device = AuthToken.objects.create(user=user).key

    status, _ = change_password(api_request, auth_token, user, signing_key)

    assert status == 204
    assert collection_list_status(api_request, auth_token) == 200
    assert collection_list_status(api_request, token_of_other_device) == 401
    assert collection_list_status(api_request, other_auth_token) == 200
    assert bytes(models.UserInfo.objects.get(owner=user).loginPubkey) == NEW_LOGIN_PUBKEY


def test_rejected_password_change_keeps_the_sessions(api_request, user, auth_token, signing_key):
    token_of_other_device = AuthToken.objects.create(user=user).key

    status, body = change_password(api_request, auth_token, user, nacl.signing.SigningKey.generate())

    assert status == 401
    assert body["code"] == "login_bad_signature"
    assert collection_list_status(api_request, token_of_other_device) == 200
    assert bytes(models.UserInfo.objects.get(owner=user).encryptedContent) == b"old"
