import typing as t

from django.db import IntegrityError, transaction
from django.db.models import QuerySet
from fastapi import APIRouter, Depends, Request, status

from etebase_server.django import models
from etebase_server.django.utils import CallbackContext, get_user_queryset
from etebase_server.myauth.models import UserType, get_typed_user_model

from ..db_hack import django_db_cleanup_decorator
from ..exceptions import HttpError, PermissionDenied
from ..msgpack import MsgpackRoute
from ..utils import (
    PERMISSIONS_READ,
    PERMISSIONS_READWRITE,
    BaseModel,
    Context,
    get_object_or_404,
    get_user_username_email_kwargs,
    is_collection_admin,
    permission_responses,
)
from .authentication import get_authenticated_user

User = get_typed_user_model()
invitation_incoming_router = APIRouter(route_class=MsgpackRoute, responses=permission_responses)
invitation_outgoing_router = APIRouter(route_class=MsgpackRoute, responses=permission_responses)
InvitationQuerySet = QuerySet[models.CollectionInvitation]
default_queryset: InvitationQuerySet = models.CollectionInvitation.objects.all()


class UserInfoOut(BaseModel):
    pubkey: bytes

    class Config:
        from_attributes= True

    @classmethod
    def from_orm(cls: t.Type["UserInfoOut"], obj: models.UserInfo) -> "UserInfoOut":
        return cls(pubkey=bytes(obj.pubkey))


class CollectionInvitationAcceptIn(BaseModel):
    collectionType: bytes
    encryptionKey: bytes


class CollectionInvitationCommon(BaseModel):
    uid: str
    version: int
    accessLevel: models.AccessLevels
    username: str
    collection: str
    signedEncryptionKey: bytes


class CollectionInvitationIn(CollectionInvitationCommon):
    def validate_db(self, context: Context):
        user = context.user
        if user is not None and (user.username == self.username.lower()):
            raise HttpError("no_self_invite", "Inviting yourself is not allowed")


class CollectionInvitationOut(CollectionInvitationCommon):
    fromUsername: str
    fromPubkey: bytes

    class Config:
        from_attributes = True

    @classmethod
    def from_orm(cls: t.Type["CollectionInvitationOut"], obj: models.CollectionInvitation) -> "CollectionInvitationOut":
        return cls(
            uid=obj.uid,
            version=obj.version,
            accessLevel=obj.accessLevel,
            username=obj.user.username,
            collection=obj.collection.uid,
            fromUsername=obj.fromMember.user.username,
            fromPubkey=bytes(obj.fromMember.user.userinfo.pubkey),
            signedEncryptionKey=bytes(obj.signedEncryptionKey),
        )


class InvitationListResponse(BaseModel):
    data: t.List[CollectionInvitationOut]
    iterator: t.Optional[str]
    done: bool


@django_db_cleanup_decorator
def get_incoming_queryset(user: UserType = Depends(get_authenticated_user)):
    return default_queryset.filter(user=user)


@django_db_cleanup_decorator
def get_outgoing_queryset(user: UserType = Depends(get_authenticated_user)):
    return default_queryset.filter(fromMember__user=user)


def list_common(
    queryset: InvitationQuerySet,
    iterator: t.Optional[str],
    limit: int,
) -> InvitationListResponse:
    queryset = queryset.order_by("id")

    if iterator is not None:
        iterator_obj = get_object_or_404(queryset, uid=iterator)
        queryset = queryset.filter(id__gt=iterator_obj.id)

    result = list(queryset[: limit + 1])
    if len(result) < limit + 1:
        done = True
    else:
        done = False
        result = result[:-1]

    ret_data = result
    iterator = ret_data[-1].uid if len(result) > 0 else None

    return InvitationListResponse(
        data=ret_data,
        iterator=iterator,
        done=done,
    )


@invitation_incoming_router.get("/", response_model=InvitationListResponse, dependencies=PERMISSIONS_READ)
def incoming_list(
    iterator: t.Optional[str] = None,
    limit: int = 50,
    queryset: InvitationQuerySet = Depends(get_incoming_queryset),
):
    return list_common(queryset, iterator, limit)


@invitation_incoming_router.get(
    "/{invitation_uid}/", response_model=CollectionInvitationOut, dependencies=PERMISSIONS_READ
)
def incoming_get(
    invitation_uid: str,
    queryset: InvitationQuerySet = Depends(get_incoming_queryset),
):
    obj = get_object_or_404(queryset, uid=invitation_uid)
    return CollectionInvitationOut.from_orm(obj)


@invitation_incoming_router.delete(
    "/{invitation_uid}/", status_code=status.HTTP_204_NO_CONTENT, dependencies=PERMISSIONS_READWRITE
)
def incoming_delete(
    invitation_uid: str,
    queryset: InvitationQuerySet = Depends(get_incoming_queryset),
):
    obj = get_object_or_404(queryset, uid=invitation_uid)
    obj.delete()


@invitation_incoming_router.post(
    "/{invitation_uid}/accept/", status_code=status.HTTP_201_CREATED, dependencies=PERMISSIONS_READWRITE
)
def incoming_accept(
    invitation_uid: str,
    data: CollectionInvitationAcceptIn,
    queryset: InvitationQuerySet = Depends(get_incoming_queryset),
):
    invitation = get_object_or_404(queryset, uid=invitation_uid)

    with transaction.atomic():
        user = invitation.user
        collection_type_obj, _ = models.CollectionType.objects.get_or_create(uid=data.collectionType, owner=user)

        models.CollectionMember.objects.create(
            collection=invitation.collection,
            stoken=models.Stoken.objects.create(),
            user=user,
            accessLevel=invitation.accessLevel,
            encryptionKey=data.encryptionKey,
            collectionType=collection_type_obj,
        )

        models.CollectionMemberRemoved.objects.filter(user=invitation.user, collection=invitation.collection).delete()

        invitation.delete()


@invitation_outgoing_router.post("/", status_code=status.HTTP_201_CREATED, dependencies=PERMISSIONS_READWRITE)
def outgoing_create(
    data: CollectionInvitationIn,
    request: Request,
    user: UserType = Depends(get_authenticated_user),
):
    collection = get_object_or_404(models.Collection.objects, uid=data.collection)
    kwargs = get_user_username_email_kwargs(data.username)
    to_user = get_object_or_404(get_user_queryset(User.objects.all(), CallbackContext(request.path_params)), **kwargs)

    context = Context(user, None)
    data.validate_db(context)

    if not is_collection_admin(collection, user):
        raise PermissionDenied("admin_access_required", "User is not an admin of this collection")

    member = collection.members.get(user=user)

    with transaction.atomic():
        try:
            models.CollectionInvitation.objects.create(
                **data.dict(exclude={"collection", "username"}), user=to_user, fromMember=member
            )
        except IntegrityError:
            raise HttpError("invitation_exists", "Invitation already exists")


@invitation_outgoing_router.get("/", response_model=InvitationListResponse, dependencies=PERMISSIONS_READ)
def outgoing_list(
    iterator: t.Optional[str] = None,
    limit: int = 50,
    queryset: InvitationQuerySet = Depends(get_outgoing_queryset),
):
    return list_common(queryset, iterator, limit)


@invitation_outgoing_router.delete(
    "/{invitation_uid}/", status_code=status.HTTP_204_NO_CONTENT, dependencies=PERMISSIONS_READWRITE
)
def outgoing_delete(
    invitation_uid: str,
    queryset: InvitationQuerySet = Depends(get_outgoing_queryset),
):
    obj = get_object_or_404(queryset, uid=invitation_uid)
    obj.delete()


@invitation_outgoing_router.get("/fetch_user_profile/", response_model=UserInfoOut, dependencies=PERMISSIONS_READ)
def outgoing_fetch_user_profile(
    username: str,
    request: Request,
    user: UserType = Depends(get_authenticated_user),
):
    kwargs = get_user_username_email_kwargs(username)
    user = get_object_or_404(get_user_queryset(User.objects.all(), CallbackContext(request.path_params)), **kwargs)
    user_info = get_object_or_404(models.UserInfo.objects.all(), owner=user)
    return UserInfoOut.from_orm(user_info)
