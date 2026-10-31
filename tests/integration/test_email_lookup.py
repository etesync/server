"""An email shared by several users identifies none of them, with the same answer as an unknown email."""

import pytest

from etebase_server.django import models

from .helpers import create_collection, new_uid

SHARED_EMAIL = "shared@example.com"
UNKNOWN_EMAIL = "unknown@example.com"


@pytest.fixture
def shared_email(user, other_user):
    for u in (user, other_user):
        u.email = SHARED_EMAIL
        u.save()
    return SHARED_EMAIL


def test_login_challenge(api_request, shared_email):
    def login_challenge(email):
        return api_request("POST", "/api/v1/authentication/login_challenge/", body={"username": email})

    status, body = login_challenge(shared_email)

    assert status == 401
    assert body["code"] == "user_not_found"
    assert (status, body) == login_challenge(UNKNOWN_EMAIL)


def test_fetch_user_profile(api_request, auth_token, shared_email):
    def fetch_user_profile(email):
        path = f"/api/v1/invitation/outgoing/fetch_user_profile/?username={email}"
        return api_request("GET", path, token=auth_token)

    status, body = fetch_user_profile(shared_email)

    assert status == 404
    assert (status, body) == fetch_user_profile(UNKNOWN_EMAIL)


def test_invitation(api_request, auth_token, shared_email):
    col_uid = new_uid()
    assert create_collection(api_request, auth_token, col_uid)[0] == 201

    def invite(email):
        body = {
            "uid": new_uid(),
            "version": 1,
            "accessLevel": models.AccessLevels.READ_ONLY,
            "username": email,
            "collection": col_uid,
            "signedEncryptionKey": b"signed-encryption-key",
        }
        return api_request("POST", "/api/v1/invitation/outgoing/", body=body, token=auth_token)

    status, body = invite(shared_email)

    assert status == 404
    assert (status, body) == invite(UNKNOWN_EMAIL)
