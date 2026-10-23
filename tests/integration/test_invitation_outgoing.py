"""Outgoing invitations resolve only collections the inviting user is a member of."""

import pytest

from etebase_server.django import models

from .helpers import create_collection, new_uid


@pytest.fixture
def col_uid_of_user(api_request, auth_token):
    col_uid = new_uid()
    assert create_collection(api_request, auth_token, col_uid)[0] == 201
    return col_uid


def invite(api_request, token, col_uid, username):
    body = {
        "uid": new_uid(),
        "version": 1,
        "accessLevel": models.AccessLevels.READ_ONLY,
        "username": username,
        "collection": col_uid,
        "signedEncryptionKey": b"signed-encryption-key",
    }
    return api_request("POST", "/api/v1/invitation/outgoing/", body=body, token=token)


def test_invite_to_collection_of_other_user_looks_like_missing_collection(
    api_request, user, other_auth_token, col_uid_of_user
):
    foreign = invite(api_request, other_auth_token, col_uid_of_user, user.username)
    missing = invite(api_request, other_auth_token, new_uid(), user.username)

    assert foreign[0] == 404
    assert foreign == missing


def test_admin_can_invite_to_own_collection(api_request, auth_token, other_user, col_uid_of_user):
    status, _ = invite(api_request, auth_token, col_uid_of_user, other_user.username)

    assert status == 201
    assert models.CollectionInvitation.objects.filter(
        user=other_user, fromMember__collection__uid=col_uid_of_user
    ).exists()


def test_member_without_admin_access_cannot_invite(api_request, user, other_user, other_auth_token, col_uid_of_user):
    models.CollectionMember.objects.create(
        collection=models.Collection.objects.get(uid=col_uid_of_user),
        user=other_user,
        accessLevel=models.AccessLevels.READ_ONLY,
        encryptionKey=b"encryption-key",
    )

    status, body = invite(api_request, other_auth_token, col_uid_of_user, user.username)

    assert status == 403
    assert body["code"] == "admin_access_required"
