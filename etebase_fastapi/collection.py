import dataclasses
import typing as t

from asgiref.sync import sync_to_async
from django.contrib.auth import get_user_model
from django.core import exceptions as django_exceptions
from django.core.files.base import ContentFile
from django.db import transaction
from django.db.models import Q
from django.db.models import QuerySet
from fastapi import APIRouter, Depends, status, Query, Request
from pydantic import BaseModel

from django_etebase import models
from django_etebase.models import Collection, AccessLevels, CollectionMember
from .authentication import get_authenticated_user
from .exceptions import ValidationError, transform_validation_error
from .msgpack import MsgpackRoute, MsgpackResponse
from .stoken_handler import filter_by_stoken_and_limit

User = get_user_model()
collection_router = APIRouter(route_class=MsgpackRoute)
default_queryset: QuerySet = Collection.objects.all()


Prefetch = t.Literal["auto", "medium"]
PrefetchQuery = Query(default="auto")


@dataclasses.dataclass
class Context:
    user: t.Optional[User]
    prefetch: t.Optional[Prefetch]


class ListMulti(BaseModel):
    collectionTypes: t.List[bytes]


class CollectionItemRevision(BaseModel):
    uid: str
    meta: bytes
    deleted: bool
    chunks: t.List[t.Tuple[str, t.Optional[bytes]]]

    class Config:
        orm_mode = True

    @classmethod
    def from_orm_context(
        cls: t.Type["CollectionItemRevision"], obj: models.CollectionItemRevision, context: Context
    ) -> "CollectionItemRevision":
        chunk_obj = obj.chunks_relation.get().chunk
        if context.prefetch == "auto":
            with open(chunk_obj.chunkFile.path, "rb") as f:
                chunks = chunk_obj.uid, f.read()
        else:
            chunks = (chunk_obj.uid,)
        return cls(uid=obj.uid, meta=obj.meta, deleted=obj.deleted, chunks=[chunks])


class CollectionItemCommon(BaseModel):
    uid: str
    version: int
    encryptionKey: t.Optional[bytes]
    content: CollectionItemRevision


class CollectionItemOut(CollectionItemCommon):
    class Config:
        orm_mode = True

    @classmethod
    def from_orm_context(
        cls: t.Type["CollectionItemOut"], obj: models.CollectionItem, context: Context
    ) -> "CollectionItemOut":
        return cls(
            uid=obj.uid,
            version=obj.version,
            encryptionKey=obj.encryptionKey,
            etag=obj.etag,
            content=CollectionItemRevision.from_orm_context(obj.content, context),
        )


class CollectionItemIn(CollectionItemCommon):
    etag: t.Optional[str]


class CollectionCommon(BaseModel):
    collectionType: bytes
    collectionKey: bytes


class CollectionOut(CollectionCommon):
    accessLevel: AccessLevels
    stoken: str
    item: CollectionItemOut

    @classmethod
    def from_orm_context(cls: t.Type["CollectionOut"], obj: Collection, context: Context) -> "CollectionOut":
        member: CollectionMember = obj.members.get(user=context.user)
        collection_type = member.collectionType
        ret = cls(
            collectionType=collection_type and collection_type.uid,
            collectionKey=member.encryptionKey,
            accessLevel=member.accessLevel,
            stoken=obj.stoken,
            item=CollectionItemOut.from_orm_context(obj.main_item, context),
        )
        return ret


class CollectionIn(CollectionCommon):
    item: CollectionItemIn


class ListResponse(BaseModel):
    data: t.List[CollectionOut]
    stoken: t.Optional[str]
    done: bool


class ItemDepIn(BaseModel):
    etag: str
    uid: str

    def validate_db(self):
        item = models.CollectionItem.objects.get(uid=self.uid)
        etag = self.etag
        if item.etag != etag:
            raise ValidationError(
                "wrong_etag",
                "Wrong etag. Expected {} got {}".format(item.etag, etag),
                status_code=status.HTTP_409_CONFLICT,
            )


class ItemBatchIn(BaseModel):
    items: t.List[CollectionItemIn]
    deps: t.Optional[ItemDepIn]

    def validate_db(self):
        if self.deps is not None:
            for key, _value in self.deps:
                getattr(self.deps, key).validate_db()


@sync_to_async
def list_common(
    queryset: QuerySet, user: User, stoken: t.Optional[str], limit: int, prefetch: Prefetch
) -> MsgpackResponse:
    result, new_stoken_obj, done = filter_by_stoken_and_limit(stoken, limit, queryset, Collection.stoken_annotation)
    new_stoken = new_stoken_obj and new_stoken_obj.uid
    context = Context(user, prefetch)
    data: t.List[CollectionOut] = [CollectionOut.from_orm_context(item, context) for item in result]
    ret = ListResponse(data=data, stoken=new_stoken, done=done)
    return MsgpackResponse(content=ret)


def get_collection_queryset(user: User, queryset: QuerySet) -> QuerySet:
    return queryset.filter(members__user=user)


@collection_router.post("/list_multi/")
async def list_multi(
    data: ListMulti,
    stoken: t.Optional[str] = None,
    limit: int = 50,
    user: User = Depends(get_authenticated_user),
    prefetch: Prefetch = PrefetchQuery,
):
    queryset = get_collection_queryset(user, default_queryset)
    # FIXME: Remove the isnull part once we attach collection types to all objects ("collection-type-migration")
    queryset = queryset.filter(
        Q(members__collectionType__uid__in=data.collectionTypes) | Q(members__collectionType__isnull=True)
    )
    response = await list_common(queryset, user, stoken, limit, prefetch)
    return response


@collection_router.post("/list/")
async def collection_list(
    req: Request,
    user: User = Depends(get_authenticated_user),
):
    pass


def process_revisions_for_item(item: models.CollectionItem, revision_data: CollectionItemRevision):
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
            uid=data.item.uid, version=data.item.version, collection=instance
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


@collection_router.get("/{uid}/")
def get_collection(uid: str, user: User = Depends(get_authenticated_user), prefetch: Prefetch = PrefetchQuery):
    obj = get_collection_queryset(user, default_queryset).get(uid=uid)
    ret = CollectionOut.from_orm_context(obj, Context(user, prefetch))
    return MsgpackResponse(ret)


def item_create(item_model: CollectionItemIn, validate_etag: bool):
    """Function that's called when this serializer creates an item"""
    etag = item_model.etag
    revision_data = item_model.content
    uid = item_model.uid

    Model = models.CollectionItem

    with transaction.atomic():
        instance, created = Model.objects.get_or_create(
            uid=uid, defaults=item_model.dict(exclude={"uid", "etag", "content"})
        )
        cur_etag = instance.etag if not created else None

        # If we are trying to update an up to date item, abort early and consider it a success
        if cur_etag == revision_data.uid:
            return instance

        if validate_etag and cur_etag != etag:
            raise ValidationError(
                "wrong_etag",
                "Wrong etag. Expected {} got {}".format(cur_etag, etag),
                status_code=status.HTTP_409_CONFLICT,
            )

        if not created:
            # We don't have to use select_for_update here because the unique constraint on current guards against
            # the race condition. But it's a good idea because it'll lock and wait rather than fail.
            current_revision = instance.revisions.filter(current=True).select_for_update().first()
            current_revision.current = None
            current_revision.save()

        try:
            process_revisions_for_item(instance, revision_data)
        except django_exceptions.ValidationError as e:
            transform_validation_error("content", e)

    return instance


def item_bulk_common(data: ItemBatchIn, user: User, stoken: t.Optional[str], uid: str, validate_etag: bool):
    queryset = get_collection_queryset(user, default_queryset)
    with transaction.atomic():  # We need this for locking the collection object
        collection_object = queryset.select_for_update().get(uid=uid)

        if stoken is not None and stoken != collection_object.stoken:
            raise ValidationError("stale_stoken", "Stoken is too old", status_code=status.HTTP_409_CONFLICT)

        # XXX-TOM: make sure we return compatible errors
        data.validate_db()
        for item in data.items:
            item_create(item, validate_etag)

        return MsgpackResponse({})


@collection_router.post("/{uid}/item/transaction/")
def item_transaction(
    uid: str, data: ItemBatchIn, stoken: t.Optional[str] = None, user: User = Depends(get_authenticated_user)
):
    item_bulk_common(data, user, stoken, uid, validate_etag=True)


@collection_router.post("/{uid}/item/batch/")
def item_batch(
    uid: str, data: ItemBatchIn, stoken: t.Optional[str] = None, user: User = Depends(get_authenticated_user)
):
    item_bulk_common(data, user, stoken, uid, validate_etag=False)
