"""Shared fixtures for the FastAPI endpoint tests.

Provides:
- ``app``          : the real ASGI app built by ``create_application`` (session-scoped).
- ``api_request``  : a synchronous ASGI driver to issue msgpack requests without httpx.
- ``user`` / ``auth_token`` : user and token created via the ORM (they need a transactional
  DB, because the sync endpoints run in the threadpool and must see committed data).
"""

import asyncio
import os

import msgpack
import pytest
from django.conf import settings

from etebase_server.fastapi.utils import msgpack_encode


@pytest.fixture(scope="session")
def app():
    # create_application mounts StaticFiles on STATIC_ROOT and installs TrustedHostMiddleware:
    # in tests the dir does not exist and ALLOWED_HOSTS is empty, so we set them before building.
    settings.ALLOWED_HOSTS = ["*"]
    os.makedirs(settings.STATIC_ROOT, exist_ok=True)

    from etebase_server.fastapi.main import create_application

    return create_application()


@pytest.fixture
def api_request(app):
    """Drive a single HTTP request through the ASGI app and return ``(status, decoded_body)``.

    The request body is msgpack-encoded; the response is msgpack-decoded (falling back to raw
    bytes for non-msgpack responses, e.g. FastAPI's default 401/403).
    """

    def _request(method, path, *, body=None, token=None):
        raw = msgpack_encode(body) if body is not None else b""
        url_path, _, query = path.partition("?")

        headers = [(b"host", b"testserver"), (b"accept", b"application/msgpack")]
        if body is not None:
            headers.append((b"content-type", b"application/msgpack"))
        if token is not None:
            headers.append((b"authorization", f"Token {token}".encode()))

        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method,
            "path": url_path,
            "raw_path": url_path.encode(),
            "query_string": query.encode(),
            "headers": headers,
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("testclient", 1),
            "root_path": "",
        }

        async def receive():
            return {"type": "http.request", "body": raw, "more_body": False}

        captured = {"status": None, "body": b""}

        async def send(message):
            if message["type"] == "http.response.start":
                captured["status"] = message["status"]
            elif message["type"] == "http.response.body":
                captured["body"] += message.get("body", b"")

        asyncio.run(app(scope, receive, send))

        out = captured["body"]
        try:
            decoded = msgpack.unpackb(out, raw=False) if out else None
        except Exception:
            decoded = out
        return captured["status"], decoded

    return _request


@pytest.fixture
def user(transactional_db):
    from etebase_server.myauth.models import get_typed_user_model

    User = get_typed_user_model()
    return User.objects.create(username="testuser", email="testuser@example.com")


@pytest.fixture
def auth_token(user):
    from etebase_server.django.token_auth.models import AuthToken

    return AuthToken.objects.create(user=user).key
