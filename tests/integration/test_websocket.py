"""Websocket sessions against a fake Redis.

Item updates reach active members only, and every session releases its pub/sub connection when it ends.
"""

import asyncio

import msgpack
import pytest
from fastapi import status

from etebase_server.django import models
from etebase_server.myauth.models import get_typed_user_model

from .helpers import create_collection, item_payload, new_uid, upload_items
from .websocket_helpers import WebSocketSession, eventually, fake_redis


@pytest.fixture
def col_uid(api_request, auth_token):
    uid = new_uid()
    assert create_collection(api_request, auth_token, uid)[0] == 201
    return uid


def add_member(col_uid, user):
    return models.CollectionMember.objects.create(
        collection=models.Collection.objects.get(uid=col_uid),
        user=user,
        accessLevel=models.AccessLevels.READ_ONLY,
        encryptionKey=b"encryption-key",
    )


async def get_ticket(async_api_request, token, col_uid):
    status_code, body = await async_api_request(
        "POST", f"/api/v1/collection/{col_uid}/item/subscription-ticket/", token=token
    )
    assert status_code == 200
    return body["ticket"]


async def subscribe(app, async_api_request, token, col_uid):
    """Open a session and consume the catch-up message with the items already in the collection."""
    session = WebSocketSession(app, f"/api/v1/ws/{await get_ticket(async_api_request, token, col_uid)}/")
    await session.next_message()
    return session


def test_ended_session_releases_its_subscription(app, async_api_request, auth_token, col_uid):
    async def scenario():
        async with fake_redis() as redis:
            session = await subscribe(app, async_api_request, auth_token, col_uid)

            await session.disconnect()

            await eventually(lambda: redis.subscriber_count() == 0)

    asyncio.run(scenario())


def test_refused_session_releases_its_subscription(app, async_api_request, other_user, other_auth_token, col_uid):
    membership = add_member(col_uid, other_user)

    async def scenario():
        async with fake_redis() as redis:
            ticket = await get_ticket(async_api_request, other_auth_token, col_uid)
            await asyncio.to_thread(membership.delete)
            session = WebSocketSession(app, f"/api/v1/ws/{ticket}/")

            await session.wait_finished()

            assert session.close_code == status.WS_1008_POLICY_VIOLATION
            await eventually(lambda: redis.subscriber_count() == 0)

    asyncio.run(scenario())


def test_member_receives_items_uploaded_after_subscribing(
    app, async_api_request, auth_token, other_user, other_auth_token, col_uid
):
    add_member(col_uid, other_user)

    async def scenario():
        async with fake_redis():
            session = await subscribe(app, async_api_request, other_auth_token, col_uid)
            item_uid = new_uid()
            assert (await upload_items(async_api_request, auth_token, col_uid, [item_payload(item_uid)]))[0] == 200

            update = msgpack.unpackb(await session.next_message(), raw=False)

            assert [item["uid"] for item in update["data"]] == [item_uid]
            await session.disconnect()

    asyncio.run(scenario())


async def remove_member(async_api_request, owner_token, col_uid, member):
    path = f"/api/v1/collection/{col_uid}/member/{member.username}/"
    assert (await async_api_request("DELETE", path, token=owner_token))[0] == 204


async def deactivate_user(async_api_request, owner_token, col_uid, member):
    await asyncio.to_thread(get_typed_user_model().objects.filter(pk=member.pk).update, is_active=False)


@pytest.mark.parametrize("revoke_access", [remove_member, deactivate_user], ids=["removed", "deactivated"])
def test_member_who_loses_access_receives_no_more_items(
    app, async_api_request, auth_token, other_user, other_auth_token, col_uid, revoke_access
):
    add_member(col_uid, other_user)

    async def scenario():
        async with fake_redis() as redis:
            session = await subscribe(app, async_api_request, other_auth_token, col_uid)
            await revoke_access(async_api_request, auth_token, col_uid, other_user)
            assert (await upload_items(async_api_request, auth_token, col_uid, [item_payload(new_uid())]))[0] == 200

            await session.wait_finished()

            assert session.close_code == status.WS_1008_POLICY_VIOLATION
            assert session.messages.empty()
            await eventually(lambda: redis.subscriber_count() == 0)

    asyncio.run(scenario())


def test_user_deactivated_after_getting_a_ticket_cannot_subscribe(app, async_api_request, user, auth_token, col_uid):
    async def scenario():
        async with fake_redis():
            ticket = await get_ticket(async_api_request, auth_token, col_uid)
            await asyncio.to_thread(get_typed_user_model().objects.filter(pk=user.pk).update, is_active=False)
            session = WebSocketSession(app, f"/api/v1/ws/{ticket}/")

            await session.wait_finished()

            assert session.close_code == status.WS_1008_POLICY_VIOLATION
            assert session.messages.empty()

    asyncio.run(scenario())


def test_session_closes_when_the_client_sends_data(app, async_api_request, auth_token, col_uid):
    async def scenario():
        async with fake_redis():
            session = await subscribe(app, async_api_request, auth_token, col_uid)

            await session.send(b"data")

            await session.wait_finished()
            assert session.close_code == status.WS_1008_POLICY_VIOLATION

    asyncio.run(scenario())
