import typing as t

from asgiref.sync import sync_to_async
from django.contrib.auth import get_user_model
from django.core import exceptions as django_exceptions
from django.core.files.base import ContentFile
from django.db import transaction
from django.db.models import Q
from django.db.models import QuerySet
from fastapi import APIRouter, Depends, status, Request
from pydantic import BaseModel

from django_etebase import models
from .authentication import get_authenticated_user
from .exceptions import ValidationError, transform_validation_error
from .msgpack import MsgpackRoute, MsgpackResponse
from .stoken_handler import filter_by_stoken_and_limit, filter_by_stoken, get_stoken_obj, get_queryset_stoken
from .utils import get_object_or_404, Context, Prefetch, PrefetchQuery

User = get_user_model()
collection_router = APIRouter(route_class=MsgpackRoute)
default_queryset: QuerySet = models.Collection.objects.all()
default_item_queryset: QuerySet = models.CollectionItem.objects.all()


class ListMulti(BaseModel):
    collectionTypes: t.List[bytes]


class CollectionItemRevisionInOut(BaseModel):
    uid: str
    meta: bytes
    deleted: bool
    chunks: t.List[t.Tuple[str, t.Optional[bytes]]]

    class Config:
        orm_mode = True

    @classmethod
    def from_orm_context(
        cls: t.Type["CollectionItemRevisionInOut"], obj: models.CollectionItemRevision, context: Context
    ) -> "CollectionItemRevisionInOut":
        chunks = []
        for chunk_relation in obj.chunks_relation.all():
            chunk_obj = chunk_relation.chunk
            if context.prefetch == "auto":
                with open(chunk_obj.chunkFile.path, "rb") as f:
                    chunks.append((chunk_obj.uid, f.read()))
            else:
                chunks.append((chunk_obj.uid,))
        return cls(uid=obj.uid, meta=obj.meta, deleted=obj.deleted, chunks=chunks)


class CollectionItemCommon(BaseModel):
    uid: str
    version: int
    encryptionKey: t.Optional[bytes]
    content: CollectionItemRevisionInOut


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
            content=CollectionItemRevisionInOut.from_orm_context(obj.content, context),
        )


class CollectionItemIn(CollectionItemCommon):
    etag: t.Optional[str]


class CollectionCommon(BaseModel):
    collectionType: bytes
    collectionKey: bytes


class CollectionOut(CollectionCommon):
    accessLevel: models.AccessLevels
    stoken: str
    item: CollectionItemOut

    @classmethod
    def from_orm_context(cls: t.Type["CollectionOut"], obj: models.Collection, context: Context) -> "CollectionOut":
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


class RemovedMembershipOut(BaseModel):
    uid: str


class CollectionListResponse(BaseModel):
    data: t.List[CollectionOut]
    stoken: t.Optional[str]
    done: bool

    removedMemberships: t.Optional[t.List[RemovedMembershipOut]]


class CollectionItemListResponse(BaseModel):
    data: t.List[CollectionItemOut]
    stoken: t.Optional[str]
    done: bool


class CollectionItemRevisionListResponse(BaseModel):
    data: t.List[CollectionItemRevisionInOut]
    iterator: t.Optional[str]
    done: bool


class CollectionItemBulkGetIn(BaseModel):
    uid: str
    etag: t.Optional[str]


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
def collection_list_common(
    queryset: QuerySet,
    user: User,
    stoken: t.Optional[str],
    limit: int,
    prefetch: Prefetch,
) -> MsgpackResponse:
    result, new_stoken_obj, done = filter_by_stoken_and_limit(
        stoken, limit, queryset, models.Collection.stoken_annotation
    )
    new_stoken = new_stoken_obj and new_stoken_obj.uid
    context = Context(user, prefetch)
    data: t.List[CollectionOut] = [CollectionOut.from_orm_context(item, context) for item in result]

    stoken_obj = get_stoken_obj(stoken)
    removedMemberships = None
    if stoken_obj is not None:
        # FIXME: honour limit? (the limit should be combined for data and this because of stoken)
        remed_qs = models.CollectionMemberRemoved.objects.filter(user=user, stoken__id__gt=stoken_obj.id)
        if not done and new_stoken_obj is not None:
            # We only filter by the new_stoken if we are not done. This is because if we are done, the new stoken
            # can point to the most recent collection change rather than most recent removed membership.
            remed_qs = remed_qs.filter(stoken__id__lte=new_stoken_obj.id)

        remed = remed_qs.values_list("collection__uid", flat=True)
        if len(remed) > 0:
            removedMemberships = [{"uid": x} for x in remed]

    ret = CollectionListResponse(data=data, stoken=new_stoken, done=done, removedMemberships=removedMemberships)
    return MsgpackResponse(content=ret)


def get_collection_queryset(user: User, queryset: QuerySet) -> QuerySet:
    return queryset.filter(members__user=user)


def get_item_queryset(
    user: User, collection_uid: str, queryset: QuerySet = default_item_queryset
) -> t.Tuple[models.Collection, QuerySet]:
    collection = get_object_or_404(get_collection_queryset(user, models.Collection.objects), uid=collection_uid)
    # XXX Potentially add this for performance: .prefetch_related('revisions__chunks')
    queryset = queryset.filter(collection__pk=collection.pk, revisions__current=True)

    return collection, queryset


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

    return await collection_list_common(queryset, user, stoken, limit, prefetch)


@collection_router.post("/list/")
async def collection_list(
    req: Request,
    stoken: t.Optional[str] = None,
    limit: int = 50,
    prefetch: Prefetch = PrefetchQuery,
    user: User = Depends(get_authenticated_user),
):
    queryset = get_collection_queryset(user, default_queryset)
    return await collection_list_common(queryset, user, stoken, limit, prefetch)


def process_revisions_for_item(item: models.CollectionItem, revision_data: CollectionItemRevisionInOut):
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
def collection_get(uid: str, user: User = Depends(get_authenticated_user), prefetch: Prefetch = PrefetchQuery):
    obj = get_collection_queryset(user, default_queryset).get(uid=uid)
    ret = CollectionOut.from_orm_context(obj, Context(user, prefetch))
    return MsgpackResponse(ret)


def item_create(item_model: CollectionItemIn, collection: models.Collection, validate_etag: bool):
    """Function that's called when this serializer creates an item"""
    etag = item_model.etag
    revision_data = item_model.content
    uid = item_model.uid

    Model = models.CollectionItem

    with transaction.atomic():
        instance, created = Model.objects.get_or_create(
            uid=uid, collection=collection, defaults=item_model.dict(exclude={"uid", "etag", "content"})
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


@collection_router.get("/{collection_uid}/item/{uid}/")
def item_get(
    collection_uid: str, uid: str, user: User = Depends(get_authenticated_user), prefetch: Prefetch = PrefetchQuery
):
    _, queryset = get_item_queryset(user, collection_uid)
    obj = queryset.get(uid=uid)
    ret = CollectionItemOut.from_orm_context(obj, Context(user, prefetch))
    return MsgpackResponse(ret)


@sync_to_async
def item_list_common(
    queryset: QuerySet,
    user: User,
    stoken: t.Optional[str],
    limit: int,
    prefetch: Prefetch,
) -> MsgpackResponse:
    result, new_stoken_obj, done = filter_by_stoken_and_limit(
        stoken, limit, queryset, models.CollectionItem.stoken_annotation
    )
    new_stoken = new_stoken_obj and new_stoken_obj.uid
    context = Context(user, prefetch)
    data: t.List[CollectionItemOut] = [CollectionItemOut.from_orm_context(item, context) for item in result]
    ret = CollectionItemListResponse(data=data, stoken=new_stoken, done=done)
    return MsgpackResponse(content=ret)


@collection_router.get("/{collection_uid}/item/")
async def item_list(
    collection_uid: str,
    stoken: t.Optional[str] = None,
    limit: int = 50,
    prefetch: Prefetch = PrefetchQuery,
    withCollection: bool = False,
    user: User = Depends(get_authenticated_user),
):
    _, queryset = await sync_to_async(get_item_queryset)(user, collection_uid)
    if not withCollection:
        queryset = queryset.filter(parent__isnull=True)

    response = await item_list_common(queryset, user, stoken, limit, prefetch)
    return response


def item_bulk_common(data: ItemBatchIn, user: User, stoken: t.Optional[str], uid: str, validate_etag: bool):
    queryset = get_collection_queryset(user, default_queryset)
    with transaction.atomic():  # We need this for locking the collection object
        collection_object = queryset.select_for_update().get(uid=uid)

        if stoken is not None and stoken != collection_object.stoken:
            raise ValidationError("stale_stoken", "Stoken is too old", status_code=status.HTTP_409_CONFLICT)

        # XXX-TOM: make sure we return compatible errors
        data.validate_db()
        for item in data.items:
            item_create(item, collection_object, validate_etag)

        return MsgpackResponse({})


@collection_router.get("/{collection_uid}/item/{uid}/revision/")
def item_revisions(
    collection_uid: str,
    uid: str,
    limit: int = 50,
    iterator: t.Optional[str] = None,
    prefetch: Prefetch = PrefetchQuery,
    user: User = Depends(get_authenticated_user),
):
    _, items = get_item_queryset(user, collection_uid)
    item = get_object_or_404(items, uid=uid)

    queryset = item.revisions.order_by("-id")

    if iterator is not None:
        iterator_obj = get_object_or_404(queryset, uid=iterator)
        queryset = queryset.filter(id__lt=iterator_obj.id)

    result = list(queryset[: limit + 1])
    if len(result) < limit + 1:
        done = True
    else:
        done = False
        result = result[:-1]

    context = Context(user, prefetch)
    ret_data = [CollectionItemRevisionInOut.from_orm_context(revision, context) for revision in result]
    iterator = ret_data[-1].uid if len(result) > 0 else None

    ret = CollectionItemRevisionListResponse(
        data=ret_data,
        iterator=iterator,
        done=done,
    )
    return MsgpackResponse(ret)


@collection_router.post("/{collection_uid}/item/fetch_updates/")
def fetch_updates(
    collection_uid: str,
    data: t.List[CollectionItemBulkGetIn],
    stoken: t.Optional[str] = None,
    prefetch: Prefetch = PrefetchQuery,
    user: User = Depends(get_authenticated_user),
):
    _, queryset = get_item_queryset(user, collection_uid)
    # FIXME: make configurable?
    item_limit = 200

    if len(data) > item_limit:
        raise ValidationError("too_many_items", "Request has too many items.", status_code=status.HTTP_400_BAD_REQUEST)

    queryset, stoken_rev = filter_by_stoken(stoken, queryset, models.CollectionItem.stoken_annotation)

    uids, etags = zip(*[(item.uid, item.etag) for item in data])
    revs = models.CollectionItemRevision.objects.filter(uid__in=etags, current=True)
    queryset = queryset.filter(uid__in=uids).exclude(revisions__in=revs)

    new_stoken_obj = get_queryset_stoken(queryset)
    new_stoken = new_stoken_obj and new_stoken_obj.uid
    stoken = stoken_rev and getattr(stoken_rev, "uid", None)
    new_stoken = new_stoken or stoken

    context = Context(user, prefetch)
    ret = CollectionItemListResponse(
        data=[CollectionItemOut.from_orm_context(item, context) for item in queryset],
        stoken=new_stoken,
        done=True,  # we always return all the items, so it's always done
    )
    return MsgpackResponse(ret)


@collection_router.post("/{collection_uid}/item/transaction/")
def item_transaction(
    collection_uid: str, data: ItemBatchIn, stoken: t.Optional[str] = None, user: User = Depends(get_authenticated_user)
):
    return item_bulk_common(data, user, stoken, collection_uid, validate_etag=True)


@collection_router.post("/{collection_uid}/item/batch/")
def item_batch(
    collection_uid: str, data: ItemBatchIn, stoken: t.Optional[str] = None, user: User = Depends(get_authenticated_user)
):
    return item_bulk_common(data, user, stoken, collection_uid, validate_etag=False)
