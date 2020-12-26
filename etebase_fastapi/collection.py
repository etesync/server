import typing as t

from asgiref.sync import sync_to_async
from django.contrib.auth import get_user_model
from django.core import exceptions as django_exceptions
from django.core.files.base import ContentFile
from django.db import transaction
from django.db.models import Q
from django.db.models import QuerySet
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

from django_etebase import models
from django_etebase.models import Collection, AccessLevels, CollectionMember
from .authentication import get_authenticated_user
from .execptions import ValidationError
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
    encryptionKey: t.Optional[bytes]
    content: CollectionItemContent


class CollectionIn(BaseModel):
    collectionType: bytes
    collectionKey: bytes
    item: Item


def process_revisions_for_item(item: models.CollectionItem, revision_data: CollectionItemContent):
    chunks_objs = []

    revision = models.CollectionItemRevision(**revision_data.dict(exclude={"chunks"}), item=item)
    revision.validate_unique()  # Verify there aren't any validation issues

    for chunk in revision_data.chunks:
        uid = chunk[0]
        chunk_obj = models.CollectionItemChunk.objects.filter(uid=uid).first()
        content = chunk[1] if len(chunk) > 1 else None
        # If the chunk already exists we assume it's fine. Otherwise, we upload it.
        if chunk_obj is None:
            if content is not None:
                chunk_obj = models.CollectionItemChunk(uid=uid, collection=item.collection)
                chunk_obj.chunkFile.save("IGNORED", ContentFile(content))
                chunk_obj.save()
            else:
                raise ValidationError("chunk_no_content", "Tried to create a new chunk without content")

        chunks_objs.append(chunk_obj)

    stoken = models.Stoken.objects.create()
    revision.stoken = stoken
    revision.save()

    for chunk in chunks_objs:
        models.RevisionChunkRelation.objects.create(chunk=chunk, revision=revision)
    return revision


def _create(data: CollectionIn, user: User):
    with transaction.atomic():
        if data.item.etag is not None:
            raise ValidationError("bad_etag", "etag is not null")
        instance = models.Collection(uid=data.item.uid, owner=user)
        try:
            instance.validate_unique()
        except django_exceptions.ValidationError:
            raise ValidationError(
                "unique_uid", "Collection with this uid already exists", status_code=status.HTTP_409_CONFLICT
            )
        instance.save()

        main_item = models.CollectionItem.objects.create(
            uid=data.item.uid, version=data.item.version, encryptionKey=data.item.encryptionKey, collection=instance
        )

        instance.main_item = main_item
        instance.save()

        # TODO
        process_revisions_for_item(main_item, data.item.content)

        collection_type_obj, _ = models.CollectionType.objects.get_or_create(uid=data.collectionType, owner=user)

        models.CollectionMember(
            collection=instance,
            stoken=models.Stoken.objects.create(),
            user=user,
            accessLevel=models.AccessLevels.ADMIN,
            encryptionKey=data.collectionKey,
            collectionType=collection_type_obj,
        ).save()


@collection_router.post("/")
async def create(data: CollectionIn, user: User = Depends(get_authenticated_user)):
    await sync_to_async(_create)(data, user)
    return MsgpackResponse({}, status_code=status.HTTP_201_CREATED)
