"""Integration smoke tests for the collection/item endpoints.

They drive real msgpack requests through the ASGI app (auth + dependency resolution + ORM).
The key signal is **404 vs 422**: before the ``collection_uid`` fix the item endpoints returned
422; with the fix, a nonexistent collection returns 404.
"""

# Plausible but nonexistent uid: it must be resolved as a path param (404), not 422.
NONEXISTENT = "0" * 64


def test_item_list_nonexistent_collection_returns_404_not_422(api_request, auth_token):
    status, _ = api_request("GET", f"/api/v1/collection/{NONEXISTENT}/item/", token=auth_token)
    assert status == 404


def test_item_batch_wellformed_body_returns_404_not_422(api_request, auth_token):
    body = {
        "items": [
            {
                "uid": "item-uid",
                "version": 1,
                "encryptionKey": b"key",
                "content": {
                    "uid": "item-uid",
                    "meta": b"meta",
                    "deleted": False,
                    "chunks": [["chunk-uid", b"data"]],
                },
                "etag": None,
            }
        ],
        "deps": None,
    }
    status, _ = api_request(
        "POST", f"/api/v1/collection/{NONEXISTENT}/item/batch/", body=body, token=auth_token
    )
    assert status == 404


def test_list_multi_returns_200(api_request, auth_token):
    status, decoded = api_request(
        "POST", "/api/v1/collection/list_multi/", body={"collectionTypes": []}, token=auth_token
    )
    assert status == 200
    assert decoded["data"] == []


def test_item_list_without_token_returns_401(api_request):
    # Missing Authorization header -> APIKeyHeader (auto_error) responds 401.
    status, _ = api_request("GET", f"/api/v1/collection/{NONEXISTENT}/item/")
    assert status == 401


def test_member_list_nonexistent_collection_returns_404_not_422(api_request, auth_token):
    # member_router is also mounted under /collection/{collection_uid}: same 422 risk,
    # covered by the same get_collection fix.
    status, _ = api_request("GET", f"/api/v1/collection/{NONEXISTENT}/member/", token=auth_token)
    assert status == 404


# batch/transaction take collection_uid as a direct endpoint param (from the router prefix).
# Without Path() it was misclassified as a required query param -> 422, but only on an EXISTING
# collection: for a missing one, get_collection short-circuits with 404 and hides it. These tests
# exercise an existing collection so the direct param is actually validated.
def test_item_batch_existing_collection_resolves_collection_uid(api_request, auth_token, collection):
    status, _ = api_request(
        "POST", f"/api/v1/collection/{collection}/item/batch/", body={"items": [], "deps": None}, token=auth_token
    )
    assert status == 200


def test_item_transaction_existing_collection_resolves_collection_uid(api_request, auth_token, collection):
    status, _ = api_request(
        "POST", f"/api/v1/collection/{collection}/item/transaction/", body={"items": [], "deps": None}, token=auth_token
    )
    assert status == 200
