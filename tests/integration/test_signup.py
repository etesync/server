"""Signup of users created by an admin, the only way to create accounts while signup is disabled."""

from etebase_server.django import models
from etebase_server.myauth.models import get_typed_user_model

SIGNUP = "/api/v1/authentication/signup/"
FAKE_KEYS = {"salt": b"s" * 16, "loginPubkey": b"l" * 32, "pubkey": b"p" * 32, "encryptedContent": b"e" * 32}


def signup_body(username, email="init@localhost"):
    # The Etebase client signs up with this placeholder email when login reports an uninitialized user.
    return {"user": {"username": username, "email": email}, **FAKE_KEYS}


def test_signup_initializes_user_created_by_admin(api_request, user):
    status, _ = api_request("POST", SIGNUP, body=signup_body(user.username))

    assert status == 200
    assert bytes(models.UserInfo.objects.get(owner=user).pubkey) == FAKE_KEYS["pubkey"]
    user.refresh_from_db()
    assert user.email == "testuser@example.com"


def test_signup_rejects_user_already_initialized(api_request, user):
    models.UserInfo.objects.create(owner=user, loginPubkey=b"old", pubkey=b"old", encryptedContent=b"old", salt=b"old")

    status, body = api_request("POST", SIGNUP, body=signup_body(user.username))

    assert status == 409
    assert body["code"] == "user_exists"
    assert bytes(models.UserInfo.objects.get(owner=user).pubkey) == b"old"


def test_signup_of_unknown_user_is_blocked_by_default(api_request, transactional_db):
    status, body = api_request("POST", SIGNUP, body=signup_body("newcomer", email="newcomer@example.com"))

    assert status == 400
    assert body["code"] == "generic"
    assert not get_typed_user_model().objects.filter(username="newcomer").exists()


def test_login_challenge_reports_uninitialized_user(api_request, user):
    # The Etebase client matches this detail to decide to sign up instead of logging in.
    status, body = api_request("POST", "/api/v1/authentication/login_challenge/", body={"username": user.username})

    assert status == 401
    assert body == {"code": "user_not_init", "detail": "User not properly init"}
