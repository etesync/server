"""Request builders for the integration tests, used together with the ``api_request`` fixture."""

import secrets


def new_uid():
    return secrets.token_urlsafe(24)


def item_payload(item_uid, chunks=(), etag=None):
    content = {"uid": new_uid(), "meta": b"meta", "deleted": False, "chunks": list(chunks)}
    return {"uid": item_uid, "version": 1, "encryptionKey": None, "content": content, "etag": etag}


def create_collection(api_request, token, col_uid, chunks=()):
    body = {
        # CollectionType.uid is unique across all users.
        "collectionType": secrets.token_bytes(16),
        "collectionKey": b"collection-key",
        "item": item_payload(col_uid, chunks),
    }
    return api_request("POST", "/api/v1/collection/", body=body, token=token)


def upload_items(api_request, token, col_uid, items, deps=None, endpoint="batch"):
    path = f"/api/v1/collection/{col_uid}/item/{endpoint}/"
    return api_request("POST", path, body={"items": items, "deps": deps}, token=token)
