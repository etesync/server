"""Transaction dependencies are validated against the items of the target collection only."""

from .helpers import create_collection, item_payload, new_uid, upload_items


def create_collection_with_item(api_request, token, item_uid):
    """Return ``(collection uid, item etag)`` of a new collection holding one item with ``item_uid``."""
    col_uid = new_uid()
    assert create_collection(api_request, token, col_uid)[0] == 201
    item = item_payload(item_uid)
    assert upload_items(api_request, token, col_uid, [item])[0] == 200
    return col_uid, item["content"]["uid"]


def transaction_with_dep(api_request, token, col_uid, dep_uid, dep_etag):
    deps = [{"uid": dep_uid, "etag": dep_etag}]
    return upload_items(api_request, token, col_uid, [item_payload(new_uid())], deps=deps, endpoint="transaction")


def dep_failed(uid, expected, got):
    return {
        "code": "dep_failed",
        "detail": "Dependencies failed to validate",
        "errors": [{"field": uid, "code": "wrong_etag", "detail": f"Wrong etag. Expected {expected} got {got}"}],
    }


def test_dep_on_missing_item_fails_with_wrong_etag(api_request, auth_token):
    col_uid, _ = create_collection_with_item(api_request, auth_token, new_uid())
    missing_uid = new_uid()

    status, body = transaction_with_dep(api_request, auth_token, col_uid, missing_uid, "etag-of-missing-item")

    assert status == 409
    assert body == dep_failed(missing_uid, expected=None, got="etag-of-missing-item")


def test_dep_on_item_of_other_collection_does_not_leak_its_etag(api_request, auth_token, other_auth_token):
    item_uid = new_uid()
    _, etag_of_user = create_collection_with_item(api_request, auth_token, item_uid)
    col_uid_of_other_user, _ = create_collection_with_item(api_request, other_auth_token, new_uid())

    status, body = transaction_with_dep(api_request, other_auth_token, col_uid_of_other_user, item_uid, "guessed-etag")

    assert status == 409
    assert body == dep_failed(item_uid, expected=None, got="guessed-etag")
    assert etag_of_user not in body["errors"][0]["detail"]


def test_dep_is_checked_on_item_of_same_collection_when_uid_is_reused(api_request, auth_token, other_auth_token):
    item_uid = new_uid()
    col_uid, etag = create_collection_with_item(api_request, auth_token, item_uid)
    _, etag_in_other_collection = create_collection_with_item(api_request, other_auth_token, item_uid)

    status, _ = transaction_with_dep(api_request, auth_token, col_uid, item_uid, etag)
    assert status == 200

    status, body = transaction_with_dep(api_request, auth_token, col_uid, item_uid, etag_in_other_collection)
    assert status == 409
    assert body == dep_failed(item_uid, expected=etag, got=etag_in_other_collection)
