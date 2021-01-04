import asyncio
import typing as t

import aioredis
from django.db.models import QuerySet
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, status
import nacl.encoding
import nacl.utils

from django_etebase import models
from django_etebase.utils import CallbackContext, get_user_queryset
from myauth.models import UserType, get_typed_user_model

from ..exceptions import NotSupported
from ..msgpack import MsgpackRoute, msgpack_decode, msgpack_encode
from ..redis import redisw
from ..utils import BaseModel, permission_responses


User = get_typed_user_model()
websocket_router = APIRouter(route_class=MsgpackRoute, responses=permission_responses)
CollectionQuerySet = QuerySet[models.Collection]


TICKET_VALIDITY_SECONDS = 10


class TicketRequest(BaseModel):
    collection: str


class TicketOut(BaseModel):
    ticket: str


class TicketInner(BaseModel):
    user: int
    req: TicketRequest


async def get_ticket(
    ticket_request: TicketRequest,
    user: UserType,
):
    """Get an authentication ticket that can be used with the websocket endpoint for authentication"""
    if not redisw.is_active:
        raise NotSupported(detail="This end-point requires Redis to be configured")

    uid = nacl.encoding.URLSafeBase64Encoder.encode(nacl.utils.random(32))
    ticket_model = TicketInner(user=user.id, req=ticket_request)
    ticket_raw = msgpack_encode(ticket_model.dict())
    await redisw.redis.set(uid, ticket_raw, expire=TICKET_VALIDITY_SECONDS * 1000)
    return TicketOut(ticket=uid)


async def load_websocket_ticket(websocket: WebSocket, ticket: str) -> t.Optional[TicketInner]:
    content = await redisw.redis.get(ticket)
    if content is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return None
    await redisw.redis.delete(ticket)
    return TicketInner(**msgpack_decode(content))


def get_websocket_user(websocket: WebSocket, ticket_model: t.Optional[TicketInner] = Depends(load_websocket_ticket)):
    if ticket_model is None:
        return None
    user_queryset = get_user_queryset(User.objects.all(), CallbackContext(websocket.path_params))
    return user_queryset.get(id=ticket_model.user)


@websocket_router.websocket("/{ticket}/")
async def websocket_endpoint(
    websocket: WebSocket,
    user: t.Optional[UserType] = Depends(get_websocket_user),
    ticket_model: TicketInner = Depends(load_websocket_ticket),
):
    if user is None:
        return
    await websocket.accept()
    await redis_connector(websocket, ticket_model)


async def redis_connector(websocket: WebSocket, ticket_model: TicketInner):
    async def producer_handler(r: aioredis.Redis, ws: WebSocket):
        channel_name = f"col.{ticket_model.req.collection}"
        (channel,) = await r.psubscribe(channel_name)
        assert isinstance(channel, aioredis.Channel)
        try:
            while True:
                # We wait on the websocket so we fail if web sockets fail or get data
                receive = asyncio.create_task(websocket.receive())
                done, pending = await asyncio.wait(
                    {receive, channel.wait_message()}, return_when=asyncio.FIRST_COMPLETED
                )
                for task in pending:
                    task.cancel()
                if receive in done:
                    # Web socket should never receieve any data
                    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    return

                message_raw = t.cast(t.Optional[t.Tuple[str, bytes]], await channel.get())
                if message_raw:
                    _, message = message_raw
                    await ws.send_bytes(message)

        except aioredis.errors.ConnectionClosedError:
            await websocket.close(code=status.WS_1012_SERVICE_RESTART)
        except WebSocketDisconnect:
            pass

    redis = redisw.redis
    await producer_handler(redis, websocket)
