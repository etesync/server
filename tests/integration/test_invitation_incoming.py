"""Incoming invitations: valid only while the sender is an active admin, and conflicts give no 500."""

import secrets

import pytest

from etebase_server.django import models
from etebase_server.myauth.models import get_typed_user_model

from .helpers import create_collection, new_uid


@pytest.fixture
def invitation_uid(api_request, auth_token, other_user):
    """An invitation from ``user`` to ``other_user`` for a new collection of ``user``."""
    col_uid = new_uid()
    assert create_collection(api_request, auth_token, col_uid)[0] == 201
    uid = new_uid()
    body = {
        "uid": uid,
        "version": 1,
        "accessLevel": models.AccessLevels.READ_ONLY,
        "username": other_user.username,
        "collection": col_uid,
        "signedEncryptionKey": b"signed-encryption-key",
    }
    assert api_request("POST", "/api/v1/invitation/outgoing/", body=body, token=auth_token)[0] == 201
    return uid


def accept(api_request, token, invitation_uid, collection_type):
    body = {"collectionType": collection_type, "encryptionKey": b"encryption-key"}
    return api_request("POST", f"/api/v1/invitation/incoming/{invitation_uid}/accept/", body=body, token=token)


def test_accepting_when_already_a_member_is_a_conflict(api_request, other_user, other_auth_token, invitation_uid):
    models.CollectionMember.objects.create(
        collection=models.CollectionInvitation.objects.get(uid=invitation_uid).collection,
        user=other_user,
        accessLevel=models.AccessLevels.READ_ONLY,
        encryptionKey=b"encryption-key",
    )

    status, body = accept(api_request, other_auth_token, invitation_uid, secrets.token_bytes(16))

    assert status == 409
    assert body["code"] == "member_exists"
    assert models.CollectionInvitation.objects.filter(uid=invitation_uid).exists()


def test_accepting_with_the_collection_type_of_another_user_is_rejected(
    api_request, user, other_user, other_auth_token, invitation_uid
):
    collection_type_of_user = bytes(models.CollectionType.objects.get(owner=user).uid)

    status, body = accept(api_request, other_auth_token, invitation_uid, collection_type_of_user)

    assert status == 400
    assert body["code"] == "bad_collection_type"
    assert not models.CollectionMember.objects.filter(user=other_user).exists()
    assert models.CollectionInvitation.objects.filter(uid=invitation_uid).exists()


def incoming_uids(api_request, token):
    status, body = api_request("GET", "/api/v1/invitation/incoming/", token=token)
    assert status == 200
    return [invitation["uid"] for invitation in body["data"]]


@pytest.fixture
def sender_keys(user):
    """Keys of ``user``, as every activated account has: the incoming list shows the sender's public key."""
    models.UserInfo.objects.create(
        owner=user, loginPubkey=b"l" * 32, pubkey=b"p" * 32, encryptedContent=b"e" * 32, salt=b"s" * 16
    )


@pytest.mark.usefixtures("sender_keys")
def test_invitation_from_an_admin_can_be_accepted(api_request, other_user, other_auth_token, invitation_uid):
    assert incoming_uids(api_request, other_auth_token) == [invitation_uid]

    status, _ = accept(api_request, other_auth_token, invitation_uid, secrets.token_bytes(16))

    assert status == 201
    assert models.CollectionMember.objects.get(user=other_user).accessLevel == models.AccessLevels.READ_ONLY


def demote(user):
    models.CollectionMember.objects.filter(user=user).update(accessLevel=models.AccessLevels.READ_ONLY)


def deactivate(user):
    get_typed_user_model().objects.filter(pk=user.pk).update(is_active=False)


@pytest.mark.parametrize("revoke_sender", [demote, deactivate], ids=["demoted", "deactivated"])
def test_invitation_from_a_sender_who_is_no_longer_an_active_admin_is_void(
    api_request, user, other_user, other_auth_token, invitation_uid, revoke_sender
):
    revoke_sender(user)

    status, body = accept(api_request, other_auth_token, invitation_uid, secrets.token_bytes(16))

    assert status == 404
    assert body["code"] == "does_not_exist"
    assert (status, body) == accept(api_request, other_auth_token, new_uid(), secrets.token_bytes(16))
    for method in ("GET", "DELETE"):
        stale = api_request(method, f"/api/v1/invitation/incoming/{invitation_uid}/", token=other_auth_token)
        assert stale[0] == 404
        assert stale == api_request(method, f"/api/v1/invitation/incoming/{new_uid()}/", token=other_auth_token)
    assert incoming_uids(api_request, other_auth_token) == []
    assert not models.CollectionMember.objects.filter(user=other_user).exists()
    assert models.CollectionInvitation.objects.filter(uid=invitation_uid).exists()
