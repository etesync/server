import typing as t

from asgiref.sync import sync_to_async
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.db.models import QuerySet
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

from django_etebase.models import Collection, AccessLevels, CollectionMember
from .authentication import get_authenticated_user
from .msgpack import MsgpackRoute, MsgpackResponse
from .stoken_handler import filter_by_stoken_and_limit

User = get_user_model()
collection_router = APIRouter(route_class=MsgpackRoute)
default_queryset = Collection.objects.all()


class ListMulti(BaseModel):
    collectionTypes: t.List[bytes]


class CollectionItemOut(BaseModel):
    uid: str


class CollectionOut(BaseModel):
    collectionKey: bytes
    collectionType: bytes
    accessLevel: AccessLevels
    stoken: str
    item: CollectionItemOut

    @classmethod
    def from_orm_user(cls: t.Type["CollectionOut"], obj: Collection, user: User) -> "CollectionOut":
        member: CollectionMember = obj.members.get(user=user)
        collection_type = member.collectionType
        return cls(
            collectionType=collection_type and collection_type.uid,
            collectionKey=member.encryptionKey,
            accessLevel=member.accessLevel,
            stoken=obj.stoken,
            item=CollectionItemOut(uid=obj.main_item.uid),
        )


class ListResponse(BaseModel):
    data: t.List[CollectionOut]
    stoken: t.Optional[str]
    done: bool


@sync_to_async
def list_common(queryset: QuerySet, user: User, stoken: t.Optional[str], limit: int) -> MsgpackResponse:
    result, new_stoken_obj, done = filter_by_stoken_and_limit(stoken, limit, queryset, Collection.stoken_annotation)
    new_stoken = new_stoken_obj and new_stoken_obj.uid
    data: t.List[CollectionOut] = [CollectionOut.from_orm_user(item, user) for item in queryset]
    ret = ListResponse(data=data, stoken=new_stoken, done=done)
    return MsgpackResponse(content=ret)


def get_collection_queryset(user: User, queryset: QuerySet) -> QuerySet:
    return queryset.filter(members__user=user)


@collection_router.post("/list_multi/")
async def list_multi(
    data: ListMulti, stoken: t.Optional[str] = None, limit: int = 50, user: User = Depends(get_authenticated_user)
):
    queryset = get_collection_queryset(user, default_queryset)
    # FIXME: Remove the isnull part once we attach collection types to all objects ("collection-type-migration")
    queryset = queryset.filter(
        Q(members__collectionType__uid__in=data.collectionTypes) | Q(members__collectionType__isnull=True)
    )
    response = await list_common(queryset, user, stoken, limit)
    return response


class CollectionItemContent(BaseModel):
    uid: str
    meta: bytes
    deleted: bool
    chunks: t.List[t.List[t.Union[str, bytes]]]


class Item(BaseModel):
    uid: str
    version: int
    etag: t.Optional[str]
    content: CollectionItemContent


class CollectionItemIn(BaseModel):
    collectionType: bytes
    collectionKey: bytes
    item: Item


@collection_router.post("/")
def create(data: CollectionItemIn):
    # FIXME save actual item
    return MsgpackResponse({}, status_code=status.HTTP_201_CREATED)
