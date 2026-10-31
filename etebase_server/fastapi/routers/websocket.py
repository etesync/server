import asyncio
import typing as t

import nacl.encoding
import nacl.utils
from asgiref.sync import sync_to_async
from django.db.models import QuerySet
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, status
from redis import asyncio as aioredis
from redis.exceptions import ConnectionError

from etebase_server.django import models
from etebase_server.django.utils import CallbackContext, get_user_queryset
from etebase_server.myauth.models import UserType, get_typed_user_model

from ..db_hack import django_db_cleanup_decorator
from ..dependencies import get_collection_queryset, get_item_queryset
from ..exceptions import NotSupported
from ..msgpack import MsgpackRoute, msgpack_decode, msgpack_encode
from ..redis import redisw
from ..utils import BaseModel, permission_responses

User = get_typed_user_model()
websocket_router = APIRouter(route_class=MsgpackRoute, responses=permission_responses)
CollectionQuerySet = QuerySet[models.Collection]


TICKET_VALIDITY_SECONDS = 60


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

    uid = nacl.encoding.URLSafeBase64Encoder.encode(nacl.utils.random(32)).decode()
    ticket_model = TicketInner(user=user.id, req=ticket_request)
    ticket_raw = msgpack_encode(ticket_model.dict())
    await redisw.redis.set(uid, ticket_raw, ex=TICKET_VALIDITY_SECONDS)
    return TicketOut(ticket=uid)


async def load_websocket_ticket(websocket: WebSocket, ticket: str) -> t.Optional[TicketInner]:
    content = await redisw.redis.get(ticket)
    if content is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return None
    await redisw.redis.delete(ticket)
    # The Redis client is created without decode_responses, so values come back as bytes.
    return TicketInner(**msgpack_decode(t.cast(bytes, content)))


def get_websocket_user(websocket: WebSocket, ticket_model: t.Optional[TicketInner] = Depends(load_websocket_ticket)):
    if ticket_model is None:
        return None
    user_queryset = get_user_queryset(User.objects.all(), CallbackContext(websocket.path_params))
    return user_queryset.get(id=ticket_model.user)


@websocket_router.websocket("/{ticket}/")
async def websocket_endpoint(
    websocket: WebSocket,
    stoken: t.Optional[str] = None,
    user: t.Optional[UserType] = Depends(get_websocket_user),
    ticket_model: TicketInner = Depends(load_websocket_ticket),
):
    if user is None:
        return
    await websocket.accept()
    await redis_connector(websocket, ticket_model, user, stoken)


async def send_item_updates(
    websocket: WebSocket,
    collection: models.Collection,
    user: UserType,
    stoken: t.Optional[str],
):
    from .collection import item_list_common

    done = False
    while not done:
        queryset = await sync_to_async(get_item_queryset)(collection)
        response = await sync_to_async(item_list_common)(queryset, user, stoken, limit=50, prefetch="auto")
        stoken, done = response.stoken, response.done
        if len(response.data) > 0:
            await websocket.send_bytes(msgpack_encode(response.dict()))


@django_db_cleanup_decorator
def has_collection_access(user: UserType, collection: models.Collection) -> bool:
    """Whether the user is still an active member of the collection, as the HTTP API requires."""
    return collection.members.filter(user=user, user__is_active=True).exists()


async def redis_connector(websocket: WebSocket, ticket_model: TicketInner, user: UserType, stoken: t.Optional[str]):
    async def producer_handler(pubsub: aioredis.client.PubSub, ws: WebSocket):
        channel_name = f"col.{ticket_model.req.collection}"
        await pubsub.subscribe(channel_name)

        # Send missing items if we are not up to date
        queryset: QuerySet[models.Collection] = get_collection_queryset(user)
        collection: t.Optional[models.Collection] = await sync_to_async(
            queryset.filter(uid=ticket_model.req.collection).first
        )()
        if collection is None or not user.is_active:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        await send_item_updates(websocket, collection, user, stoken)

        async def handle_message() -> bool:
            """Forward the next published message, if any; return False if the user lost access."""
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=20)
            if msg is None:
                return True
            if not await sync_to_async(has_collection_access)(user, collection):
                return False
            await ws.send_bytes(msg["data"])
            return True

        try:
            while True:
                # We wait on the websocket so we fail if web sockets fail or get data
                receive = asyncio.create_task(websocket.receive())
                forward = asyncio.create_task(handle_message())
                done, pending = await asyncio.wait({receive, forward}, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                if receive in done:
                    # Web socket should never receive any data
                    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    return
                if not forward.result():
                    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    return

        except ConnectionError:
            await websocket.close(code=status.WS_1012_SERVICE_RESTART)
        except WebSocketDisconnect:
            pass

    async with redisw.redis.pubsub() as pubsub:
        await producer_handler(pubsub, websocket)
