"""Chunk references in a revision resolve only within the collection of the item."""

import pytest

from etebase_server.django import models
from etebase_server.fastapi.utils import msgpack_encode

from .helpers import create_collection, item_payload, new_uid, upload_items

pytestmark = pytest.mark.usefixtures("media_root")

CIPHERTEXT_OF_USER = b"ciphertext of user"
CIPHERTEXT_OF_OTHER_USER = b"ciphertext of other user"


@pytest.fixture
def chunk_uid_of_user(api_request, auth_token):
    """UID of a chunk stored in a collection of ``user``, which ``other_user`` cannot access."""
    chunk_uid = new_uid()
    status, _ = create_collection(api_request, auth_token, new_uid(), [[chunk_uid, CIPHERTEXT_OF_USER]])
    assert status == 201
    return chunk_uid


def get_item(api_request, token, col_uid, item_uid):
    return api_request("GET", f"/api/v1/collection/{col_uid}/item/{item_uid}/", token=token)


def test_reference_to_chunk_of_other_collection_needs_content(
    api_request, other_user, other_auth_token, chunk_uid_of_user
):
    status, body = create_collection(api_request, other_auth_token, new_uid(), [[chunk_uid_of_user, None]])

    assert status == 400
    assert body["code"] == "chunk_no_content"
    assert not models.RevisionChunkRelation.objects.filter(
        chunk__uid=chunk_uid_of_user, revision__item__collection__owner=other_user
    ).exists()
    status, collections = api_request("GET", "/api/v1/collection/", token=other_auth_token)
    assert status == 200
    assert CIPHERTEXT_OF_USER not in msgpack_encode(collections)


def test_chunk_with_uid_of_other_collection_is_stored_in_own_collection(
    api_request, other_auth_token, chunk_uid_of_user
):
    col_uid = new_uid()
    assert create_collection(api_request, other_auth_token, col_uid)[0] == 201
    item_uid = new_uid()
    item = item_payload(item_uid, [[chunk_uid_of_user, CIPHERTEXT_OF_OTHER_USER]])

    status, _ = upload_items(api_request, other_auth_token, col_uid, [item])

    assert status == 200
    assert models.CollectionItemChunk.objects.filter(uid=chunk_uid_of_user).count() == 2
    status, body = get_item(api_request, other_auth_token, col_uid, item_uid)
    assert status == 200
    assert body["content"]["chunks"] == [[chunk_uid_of_user, CIPHERTEXT_OF_OTHER_USER]]


def test_chunk_of_same_collection_is_reused_without_content(api_request, auth_token):
    chunk_uid = new_uid()
    col_uid = new_uid()
    assert create_collection(api_request, auth_token, col_uid, [[chunk_uid, CIPHERTEXT_OF_USER]])[0] == 201
    item_uid = new_uid()

    status, _ = upload_items(api_request, auth_token, col_uid, [item_payload(item_uid, [[chunk_uid, None]])])

    assert status == 200
    assert models.CollectionItemChunk.objects.filter(uid=chunk_uid).count() == 1
    status, body = get_item(api_request, auth_token, col_uid, item_uid)
    assert status == 200
    assert body["content"]["chunks"] == [[chunk_uid, CIPHERTEXT_OF_USER]]
