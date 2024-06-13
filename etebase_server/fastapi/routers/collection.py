import typing as t

from asgiref.sync import sync_to_async
from django.core import exceptions as django_exceptions
from django.core.files.base import ContentFile
from django.db import IntegrityError, transaction
from django.db.models import Q, QuerySet
from fastapi import APIRouter, BackgroundTasks, Depends, Request, status

from etebase_server.django import models
from etebase_server.myauth.models import UserType

from ..db_hack import django_db_cleanup_decorator
from ..dependencies import get_collection, get_collection_queryset, get_item_queryset
from ..exceptions import HttpError, PermissionDenied, ValidationError, transform_validation_error
from ..msgpack import MsgpackRequest, MsgpackResponse, MsgpackRoute
from ..redis import redisw
from ..sendfile import sendfile
from ..stoken_handler import filter_by_stoken, filter_by_stoken_and_limit, get_queryset_stoken, get_stoken_obj
from ..utils import (
    PERMISSIONS_READ,
    PERMISSIONS_READWRITE,
    BaseModel,
    Context,
    Prefetch,
    PrefetchQuery,
    get_object_or_404,
    is_collection_admin,
    msgpack_encode,
    permission_responses,
)
from .authentication import get_authenticated_user
from .websocket import TicketOut, TicketRequest, get_ticket

collection_router = APIRouter(route_class=MsgpackRoute, responses=permission_responses)
item_router = APIRouter(route_class=MsgpackRoute, responses=permission_responses)
CollectionQuerySet = QuerySet[models.Collection]
CollectionItemQuerySet = QuerySet[models.CollectionItem]


class ListMulti(BaseModel):
    collectionTypes: t.List[bytes]


ChunkType = t.Tuple[str, t.Optional[bytes]]


class CollectionItemRevisionInOut(BaseModel):
    uid: str
    meta: bytes
    deleted: bool
    chunks: t.List[ChunkType]

    class Config:
        from_attributes = True

    @classmethod
    def from_orm_context(
        cls: t.Type["CollectionItemRevisionInOut"], obj: models.CollectionItemRevision, context: Context
    ) -> "CollectionItemRevisionInOut":
        chunks: t.List[ChunkType] = []
        for chunk_relation in obj.chunks_relation.all():
            chunk_obj = chunk_relation.chunk
            if context.prefetch == "auto":
                with open(chunk_obj.chunkFile.path, "rb") as f:
                    chunks.append((chunk_obj.uid, f.read()))
            else:
                chunks.append((chunk_obj.uid, None))
        return cls(uid=obj.uid, meta=bytes(obj.meta), deleted=obj.deleted, chunks=chunks)


class CollectionItemCommon(BaseModel):
    uid: str
    version: int
    encryptionKey: t.Optional[bytes] = None
    content: CollectionItemRevisionInOut


class CollectionItemOut(CollectionItemCommon):
    class Config:
        from_attributes = True

    @classmethod
    def from_orm_context(
        cls: t.Type["CollectionItemOut"], obj: models.CollectionItem, context: Context
    ) -> "CollectionItemOut":
        return cls(
            uid=obj.uid,
            version=obj.version,
            encryptionKey=obj.encryptionKey,
            content=CollectionItemRevisionInOut.from_orm_context(obj.content, context),
        )


class CollectionItemIn(CollectionItemCommon):
    etag: t.Optional[str] = None


class CollectionCommon(BaseModel):
    # FIXME: remove optional once we finish collection-type-migration
    collectionType: t.Optional[bytes] = None
    collectionKey: bytes


class CollectionOut(CollectionCommon):
    accessLevel: models.AccessLevels
    stoken: str
    item: CollectionItemOut

    @classmethod
    def from_orm_context(cls: t.Type["CollectionOut"], obj: models.Collection, context: Context) -> "CollectionOut":
        member: models.CollectionMember = obj.members.get(user=context.user)
        collection_type = member.collectionType
        assert obj.main_item is not None
        ret = cls(
            collectionType=collection_type and bytes(collection_type.uid),
            collectionKey=bytes(member.encryptionKey),
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
    stoken: t.Optional[str] = None
    done: bool

    removedMemberships: t.Optional[t.List[RemovedMembershipOut]] = None


class CollectionItemListResponse(BaseModel):
    data: t.List[CollectionItemOut]
    stoken: t.Optional[str] = None
    done: bool


class CollectionItemRevisionListResponse(BaseModel):
    data: t.List[CollectionItemRevisionInOut]
    iterator: t.Optional[str] = None
    done: bool


class CollectionItemBulkGetIn(BaseModel):
    uid: str
    etag: t.Optional[str] = None


class ItemDepIn(BaseModel):
    uid: str
    etag: str

    def validate_db(self):
        item = models.CollectionItem.objects.get(uid=self.uid)
        etag = self.etag
        if item.etag != etag:
            raise ValidationError(
                "wrong_etag",
                "Wrong etag. Expected {} got {}".format(item.etag, etag),
                status_code=status.HTTP_409_CONFLICT,
                field=self.uid,
            )


class ItemBatchIn(BaseModel):
    items: t.List[CollectionItemIn]
    deps: t.Optional[t.List[ItemDepIn]] = None

    def validate_db(self):
        if self.deps is not None:
            errors: t.List[HttpError] = []
            for dep in self.deps:
                try:
                    dep.validate_db()
                except ValidationError as e:
                    errors.append(e)
            if len(errors) > 0:
                raise ValidationError(
                    code="dep_failed",
                    detail="Dependencies failed to validate",
                    errors=errors,
                    status_code=status.HTTP_409_CONFLICT,
                )


async def report_items_changed(col_uid: str, stoken: str, items: t.List[CollectionItemIn]):
    if not redisw.is_active:
        return

    redis = redisw.redis
    content = msgpack_encode(CollectionItemListResponse(data=items, stoken=stoken, done=True).dict())
    await redis.publish(f"col.{col_uid}", content)


def collection_list_common(
    queryset: CollectionQuerySet,
    user: UserType,
    stoken: t.Optional[str],
    limit: int,
    prefetch: Prefetch,
) -> CollectionListResponse:
    result, new_stoken_obj, done = filter_by_stoken_and_limit(
        stoken, limit, queryset.filter(items__revisions__current=True), models.Collection.stoken_annotation
    )
    new_stoken = new_stoken_obj and new_stoken_obj.uid
    context = Context(user, prefetch)
    data: t.List[CollectionOut] = [CollectionOut.from_orm_context(item, context) for item in result]

    ret = CollectionListResponse(data=data, stoken=new_stoken, done=done)

    stoken_obj = get_stoken_obj(stoken)
    if stoken_obj is not None:
        # FIXME: honour limit? (the limit should be combined for data and this because of stoken)
        remed_qs = models.CollectionMemberRemoved.objects.filter(user=user, stoken__id__gt=stoken_obj.id)
        if not done and new_stoken_obj is not None:
            # We only filter by the new_stoken if we are not done. This is because if we are done, the new stoken
            # can point to the most recent collection change rather than most recent removed membership.
            remed_qs = remed_qs.filter(stoken__id__lte=new_stoken_obj.id)

        remed = remed_qs.values_list("collection__uid", flat=True)
        if len(remed) > 0:
            ret.removedMemberships = [RemovedMembershipOut(uid=x) for x in remed]

    return ret


# permissions


@django_db_cleanup_decorator
def verify_collection_admin(
    collection: models.Collection = Depends(get_collection), user: UserType = Depends(get_authenticated_user)
):
    if not is_collection_admin(collection, user):
        raise PermissionDenied("admin_access_required", "Only collection admins can perform this operation.")


@django_db_cleanup_decorator
def has_write_access(
    collection: models.Collection = Depends(get_collection), user: UserType = Depends(get_authenticated_user)
):
    member = collection.members.get(user=user)
    if member.accessLevel == models.AccessLevels.READ_ONLY:
        raise PermissionDenied("no_write_access", "You need write access to write to this collection")


# paths


@collection_router.post(
    "/list_multi/",
    response_model=CollectionListResponse,
    response_model_exclude_unset=True,
    dependencies=PERMISSIONS_READ,
)
def list_multi(
    data: ListMulti,
    stoken: t.Optional[str] = None,
    limit: int = 50,
    queryset: CollectionQuerySet = Depends(get_collection_queryset),
    user: UserType = Depends(get_authenticated_user),
    prefetch: Prefetch = PrefetchQuery,
):
    # FIXME: Remove the isnull part once we attach collection types to all objects ("collection-type-migration")
    queryset = queryset.filter(
        Q(members__collectionType__uid__in=data.collectionTypes) | Q(members__collectionType__isnull=True)
    )

    return MsgpackResponse(collection_list_common(queryset, user, stoken, limit, prefetch))


@collection_router.get("/", response_model=CollectionListResponse, dependencies=PERMISSIONS_READ)
def collection_list(
    stoken: t.Optional[str] = None,
    limit: int = 50,
    prefetch: Prefetch = PrefetchQuery,
    user: UserType = Depends(get_authenticated_user),
    queryset: CollectionQuerySet = Depends(get_collection_queryset),
):
    return MsgpackResponse(collection_list_common(queryset, user, stoken, limit, prefetch))


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

    for chunk2 in chunks_objs:
        models.RevisionChunkRelation.objects.create(chunk=chunk2, revision=revision)
    return revision


def _create(data: CollectionIn, user: UserType):
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


@collection_router.post("/", status_code=status.HTTP_201_CREATED, dependencies=PERMISSIONS_READWRITE)
def create(data: CollectionIn, user: UserType = Depends(get_authenticated_user)):
    _create(data, user)


@collection_router.get("/{collection_uid}/", response_model=CollectionOut, dependencies=PERMISSIONS_READ)
def collection_get(
    obj: models.Collection = Depends(get_collection),
    user: UserType = Depends(get_authenticated_user),
    prefetch: Prefetch = PrefetchQuery,
):
    return MsgpackResponse(CollectionOut.from_orm_context(obj, Context(user, prefetch)))


def item_create(item_model: CollectionItemIn, collection: models.Collection, validate_etag: bool):
    """Function that's called when this serializer creates an item"""
    etag = item_model.etag
    revision_data = item_model.content
    uid = item_model.uid

    Model = models.CollectionItem  # noqa: N806

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
                field=uid,
            )

        if not created:
            # We don't have to use select_for_update here because the unique constraint on current guards against
            # the race condition. But it's a good idea because it'll lock and wait rather than fail.
            current_revision = instance.revisions.filter(current=True).select_for_update()[0]
            assert current_revision is not None
            current_revision.current = None
            current_revision.save()

        try:
            process_revisions_for_item(instance, revision_data)
        except django_exceptions.ValidationError as e:
            transform_validation_error("content", e)

    return instance


@item_router.get("/item/{item_uid}/", response_model=CollectionItemOut, dependencies=PERMISSIONS_READ)
def item_get(
    item_uid: str,
    queryset: CollectionItemQuerySet = Depends(get_item_queryset),
    user: UserType = Depends(get_authenticated_user),
    prefetch: Prefetch = PrefetchQuery,
):
    obj = queryset.get(uid=item_uid)
    return MsgpackResponse(CollectionItemOut.from_orm_context(obj, Context(user, prefetch)))


def item_list_common(
    queryset: CollectionItemQuerySet,
    user: UserType,
    stoken: t.Optional[str],
    limit: int,
    prefetch: Prefetch,
) -> CollectionItemListResponse:
    result, new_stoken_obj, done = filter_by_stoken_and_limit(
        stoken, limit, queryset.filter(revisions__current=True), models.CollectionItem.stoken_annotation
    )
    new_stoken = new_stoken_obj and new_stoken_obj.uid
    context = Context(user, prefetch)
    data: t.List[CollectionItemOut] = [CollectionItemOut.from_orm_context(item, context) for item in result]
    return CollectionItemListResponse(data=data, stoken=new_stoken, done=done)


@item_router.get("/item/", response_model=CollectionItemListResponse, dependencies=PERMISSIONS_READ)
def item_list(
    queryset: CollectionItemQuerySet = Depends(get_item_queryset),
    stoken: t.Optional[str] = None,
    limit: int = 50,
    prefetch: Prefetch = PrefetchQuery,
    withCollection: bool = False,
    user: UserType = Depends(get_authenticated_user),
):
    if not withCollection:
        queryset = queryset.filter(parent__isnull=True)

    response = item_list_common(queryset, user, stoken, limit, prefetch)
    return MsgpackResponse(response)


@item_router.post("/item/subscription-ticket/", response_model=TicketOut, dependencies=PERMISSIONS_READ)
async def item_list_subscription_ticket(
    collection: models.Collection = Depends(get_collection),
    user: UserType = Depends(get_authenticated_user),
):
    """Get an authentication ticket that can be used with the websocket endpoint"""
    return MsgpackResponse(await get_ticket(TicketRequest(collection=collection.uid), user))


def item_bulk_common(
    data: ItemBatchIn,
    user: UserType,
    stoken: t.Optional[str],
    uid: str,
    validate_etag: bool,
    background_tasks: BackgroundTasks,
):
    queryset = get_collection_queryset(user)
    with transaction.atomic():  # We need this for locking the collection object
        collection_object = queryset.select_for_update().get(uid=uid)

        if stoken and stoken != collection_object.stoken:
            raise HttpError("stale_stoken", "Stoken is too old", status_code=status.HTTP_409_CONFLICT)

        data.validate_db()

        errors: t.List[HttpError] = []
        for item in data.items:
            try:
                item_create(item, collection_object, validate_etag)
            except ValidationError as e:
                errors.append(e)

        if len(errors) > 0:
            raise ValidationError(
                code="item_failed",
                detail="Items failed to validate",
                errors=errors,
                status_code=status.HTTP_409_CONFLICT,
            )

    background_tasks.add_task(report_items_changed, collection_object.uid, collection_object.stoken, data.items)


@item_router.get(
    "/item/{item_uid}/revision/", response_model=CollectionItemRevisionListResponse, dependencies=PERMISSIONS_READ
)
def item_revisions(
    item_uid: str,
    limit: int = 50,
    iterator: t.Optional[str] = None,
    prefetch: Prefetch = PrefetchQuery,
    user: UserType = Depends(get_authenticated_user),
    items: CollectionItemQuerySet = Depends(get_item_queryset),
):
    item = get_object_or_404(items, uid=item_uid)

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

    return MsgpackResponse(
        CollectionItemRevisionListResponse(
            data=ret_data,
            iterator=iterator,
            done=done,
        )
    )


@item_router.post("/item/fetch_updates/", response_model=CollectionItemListResponse, dependencies=PERMISSIONS_READ)
def fetch_updates(
    data: t.List[CollectionItemBulkGetIn],
    stoken: t.Optional[str] = None,
    prefetch: Prefetch = PrefetchQuery,
    user: UserType = Depends(get_authenticated_user),
    queryset: CollectionItemQuerySet = Depends(get_item_queryset),
):
    # FIXME: make configurable?
    item_limit = 200

    if len(data) > item_limit:
        raise HttpError("too_many_items", "Request has too many items.", status_code=status.HTTP_400_BAD_REQUEST)

    queryset, stoken_rev = filter_by_stoken(stoken, queryset, models.CollectionItem.stoken_annotation)

    uids, etags = zip(*[(item.uid, item.etag) for item in data])
    revs = models.CollectionItemRevision.objects.filter(uid__in=etags, current=True)
    queryset = queryset.filter(uid__in=uids).exclude(revisions__in=revs)

    new_stoken_obj = get_queryset_stoken(queryset)
    new_stoken = new_stoken_obj and new_stoken_obj.uid
    stoken_rev_uid = stoken_rev and getattr(stoken_rev, "uid", None)
    new_stoken = new_stoken or stoken_rev_uid

    context = Context(user, prefetch)
    return MsgpackResponse(
        CollectionItemListResponse(
            data=[CollectionItemOut.from_orm_context(item, context) for item in queryset],
            stoken=new_stoken,
            done=True,  # we always return all the items, so it's always done
        )
    )


@item_router.post("/item/transaction/", dependencies=[Depends(has_write_access), *PERMISSIONS_READWRITE])
def item_transaction(
    collection_uid: str,
    data: ItemBatchIn,
    background_tasks: BackgroundTasks,
    stoken: t.Optional[str] = None,
    user: UserType = Depends(get_authenticated_user),
):
    return MsgpackResponse(
        item_bulk_common(data, user, stoken, collection_uid, validate_etag=True, background_tasks=background_tasks)
    )


@item_router.post("/item/batch/", dependencies=[Depends(has_write_access), *PERMISSIONS_READWRITE])
def item_batch(
    collection_uid: str,
    data: ItemBatchIn,
    background_tasks: BackgroundTasks,
    stoken: t.Optional[str] = None,
    user: UserType = Depends(get_authenticated_user),
):
    return MsgpackResponse(
        item_bulk_common(data, user, stoken, collection_uid, validate_etag=False, background_tasks=background_tasks)
    )


# Chunks


@sync_to_async
def chunk_save(chunk_uid: str, collection: models.Collection, content_file: ContentFile):
    chunk_obj = models.CollectionItemChunk(uid=chunk_uid, collection=collection)
    chunk_obj.chunkFile.save("IGNORED", content_file)
    chunk_obj.save()
    return chunk_obj


@item_router.put(
    "/item/{item_uid}/chunk/{chunk_uid}/",
    dependencies=[Depends(has_write_access), *PERMISSIONS_READWRITE],
    status_code=status.HTTP_201_CREATED,
)
async def chunk_update(
    request: Request,
    chunk_uid: str,
    collection: models.Collection = Depends(get_collection),
):
    # IGNORED FOR NOW: col_it = get_object_or_404(col.items, uid=collection_item_uid)
    if isinstance(request, MsgpackRequest):
        body = await request.raw_body()
    else:
        body = await request.body()

    content_file = ContentFile(body)
    try:
        await chunk_save(chunk_uid, collection, content_file)
    except IntegrityError:
        raise HttpError("chunk_exists", "Chunk already exists.", status_code=status.HTTP_409_CONFLICT)


@item_router.get(
    "/item/{item_uid}/chunk/{chunk_uid}/download/",
    dependencies=PERMISSIONS_READ,
)
def chunk_download(
    chunk_uid: str,
    collection: models.Collection = Depends(get_collection),
):
    chunk = get_object_or_404(collection.chunks, uid=chunk_uid)

    filename = chunk.chunkFile.path
    return sendfile(filename)
