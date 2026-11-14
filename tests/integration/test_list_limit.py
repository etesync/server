"""The page size of the list endpoints is at least 1, and larger requests are served in pages of MAX_LIMIT."""

import pytest

from etebase_server.fastapi import utils

from .helpers import item_payload, new_uid, upload_items

# Every endpoint that takes ``limit``; ``{col}`` is a collection of the requesting user and the uid of its item.
LIST_ENDPOINTS = {
    "collections": ("GET", "/api/v1/collection/", None),
    "list_multi": ("POST", "/api/v1/collection/list_multi/", {"collectionTypes": []}),
    "items": ("GET", "/api/v1/collection/{col}/item/", None),
    "revisions": ("GET", "/api/v1/collection/{col}/item/{col}/revision/", None),
    "members": ("GET", "/api/v1/collection/{col}/member/", None),
    "incoming invitations": ("GET", "/api/v1/invitation/incoming/", None),
    "outgoing invitations": ("GET", "/api/v1/invitation/outgoing/", None),
}


@pytest.mark.parametrize("limit", [0, -5])
@pytest.mark.parametrize("endpoint", LIST_ENDPOINTS)
def test_limit_below_one_is_rejected(api_request, auth_token, collection, endpoint, limit):
    method, path, body = LIST_ENDPOINTS[endpoint]

    status, _ = api_request(method, f"{path.format(col=collection)}?limit={limit}", body=body, token=auth_token)

    assert status == 422


def test_limit_of_one_is_accepted(api_request, auth_token, collection):
    status, body = api_request("GET", "/api/v1/collection/?limit=1", token=auth_token)

    assert status == 200
    assert len(body["data"]) == 1


def test_larger_limit_is_served_in_pages_of_max_limit(api_request, auth_token, collection, monkeypatch):
    monkeypatch.setattr(utils, "MAX_LIMIT", 2)
    item_uids = [new_uid() for _ in range(3)]
    assert upload_items(api_request, auth_token, collection, [item_payload(uid) for uid in item_uids])[0] == 200

    pages = []
    query = "limit=1000"
    for _ in item_uids:
        status, body = api_request("GET", f"/api/v1/collection/{collection}/item/?{query}", token=auth_token)
        assert status == 200
        pages.append(([item["uid"] for item in body["data"]], body["done"]))
        if body["done"]:
            break
        query = f"limit=1000&stoken={body['stoken']}"

    assert [(len(uids), done) for uids, done in pages] == [(2, False), (1, True)]
    assert sorted(uid for uids, _ in pages for uid in uids) == sorted(item_uids)
