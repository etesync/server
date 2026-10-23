"""Unit tests for the websocket ticket issued by ``get_ticket``.

Redis is replaced by a stub that records the ``SET`` calls: no database, Redis or server.
"""

import asyncio
from types import SimpleNamespace

from etebase_server.fastapi.redis import redisw
from etebase_server.fastapi.routers.websocket import TICKET_VALIDITY_SECONDS, TicketRequest, get_ticket


class RecordingRedis:
    def __init__(self):
        self.set_calls = []

    async def set(self, name, value, ex=None):
        self.set_calls.append({"name": name, "ex": ex})


def test_ticket_expires_after_validity_seconds(monkeypatch):
    redis = RecordingRedis()
    monkeypatch.setattr(redisw, "redis_uri", "redis://stub")
    monkeypatch.setattr(redisw, "redis", redis, raising=False)

    out = asyncio.run(get_ticket(TicketRequest(collection="collection-uid"), SimpleNamespace(id=1)))

    # redis-py takes ``ex`` in seconds
    assert redis.set_calls == [{"name": out.ticket.encode(), "ex": TICKET_VALIDITY_SECONDS}]
