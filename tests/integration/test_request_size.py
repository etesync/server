"""Request bodies larger than ``MAX_REQUEST_SIZE`` are rejected with 413, before authentication when possible."""

import pytest

from etebase_server.django import app_settings, models
from etebase_server.fastapi.utils import msgpack_encode

from .helpers import create_collection, item_payload, new_uid, upload_items

LIMIT = 1024

pytestmark = pytest.mark.usefixtures("media_root")


@pytest.fixture
def app(app, monkeypatch):
    """The real app, built with a request size limit of ``LIMIT`` bytes."""
    from etebase_server.fastapi.main import create_application

    monkeypatch.setitem(app_settings.__dict__, "MAX_REQUEST_SIZE", LIMIT)
    return create_application()


@pytest.fixture
def col_uid(api_request, auth_token):
    uid = new_uid()
    assert create_collection(api_request, auth_token, uid)[0] == 201
    return uid


def batch_with_a_chunk_of(size):
    return [item_payload(new_uid(), [[new_uid(), b"x" * size]])]


def assert_too_large(response):
    status, body = response
    assert status == 413
    assert body["code"] == "request_too_large"


@pytest.mark.parametrize("authenticated", [True, False], ids=["with token", "without token"])
def test_body_over_the_limit_is_rejected(api_request, auth_token, col_uid, media_root, authenticated):
    token = auth_token if authenticated else None

    assert_too_large(upload_items(api_request, token, col_uid, batch_with_a_chunk_of(LIMIT)))

    assert models.CollectionItem.objects.filter(collection__uid=col_uid).count() == 1
    assert not [f for f in media_root.rglob("*") if f.is_file()]


def test_body_under_the_limit_is_accepted(api_request, auth_token, col_uid):
    assert upload_items(api_request, auth_token, col_uid, batch_with_a_chunk_of(LIMIT // 2))[0] == 200


def test_chunk_upload_is_limited_to_the_exact_size(api_request, auth_token, col_uid, media_root):
    path = f"/api/v1/collection/{col_uid}/item/{new_uid()}/chunk/{new_uid()}/"
    largest = b"x" * (LIMIT - 3)  # msgpack adds a 3-byte header to binary data of this size
    assert len(msgpack_encode(largest)) == LIMIT

    assert_too_large(api_request("PUT", path, body=largest + b"x", token=auth_token))
    assert not [f for f in media_root.rglob("*") if f.is_file()]
    assert api_request("PUT", path, body=largest, token=auth_token)[0] == 201
