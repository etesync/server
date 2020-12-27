import typing as t

from django.contrib.auth import get_user_model
from django.db import transaction, IntegrityError
from django.db.models import QuerySet
from fastapi import APIRouter, Depends, status, Request
from pydantic import BaseModel

from django_etebase import models
from django_etebase.utils import get_user_queryset, CallbackContext
from .authentication import get_authenticated_user
from .exceptions import ValidationError, PermissionDenied
from .msgpack import MsgpackRoute, MsgpackResponse
from .utils import get_object_or_404, Context, is_collection_admin

User = get_user_model()
invitation_incoming_router = APIRouter(route_class=MsgpackRoute)
invitation_outgoing_router = APIRouter(route_class=MsgpackRoute)
default_queryset: QuerySet = models.CollectionInvitation.objects.all()


class UserInfoOut(BaseModel):
    pubkey: bytes

    class Config:
        orm_mode = True


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
        if context.user.username == self.username.lower():
            raise ValidationError("no_self_invite", "Inviting yourself is not allowed")


class CollectionInvitationOut(CollectionInvitationCommon):
    fromUsername: str
    fromPubkey: bytes

    class Config:
        orm_mode = True

    @classmethod
    def from_orm(cls: t.Type["CollectionInvitationOut"], obj: models.CollectionInvitation) -> "CollectionInvitationOut":
        return cls(
            uid=obj.uid,
            version=obj.version,
            accessLevel=obj.accessLevel,
            username=obj.user.username,
            collection=obj.collection.uid,
            fromUsername=obj.fromMember.user.username,
            fromPubkey=obj.fromMember.user.userinfo.pubkey,
            signedEncryptionKey=obj.signedEncryptionKey,
        )


class InvitationListResponse(BaseModel):
    data: t.List[CollectionInvitationOut]
    iterator: t.Optional[str]
    done: bool


def get_incoming_queryset(user: User = Depends(get_authenticated_user)):
    return default_queryset.filter(user=user)


def get_outgoing_queryset(user: User = Depends(get_authenticated_user)):
    return default_queryset.filter(fromMember__user=user)


def list_common(
    queryset: QuerySet,
    iterator: t.Optional[str],
    limit: int,
) -> MsgpackResponse:
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

    ret = InvitationListResponse(
        data=ret_data,
        iterator=iterator,
        done=done,
    )
    return MsgpackResponse(ret)


@invitation_incoming_router.get("/", response_model=InvitationListResponse)
def incoming_list(
    iterator: t.Optional[str] = None,
    limit: int = 50,
    queryset: QuerySet = Depends(get_incoming_queryset),
):
    return list_common(queryset, iterator, limit)


@invitation_incoming_router.get("/{invitation_uid}/", response_model=CollectionInvitationOut)
def incoming_get(
    invitation_uid: str,
    queryset: QuerySet = Depends(get_incoming_queryset),
):
    obj = get_object_or_404(queryset, uid=invitation_uid)
    ret = CollectionInvitationOut.from_orm(obj)
    return MsgpackResponse(ret)


@invitation_incoming_router.delete("/{invitation_uid}/", status_code=status.HTTP_204_NO_CONTENT)
def incoming_delete(
    invitation_uid: str,
    queryset: QuerySet = Depends(get_incoming_queryset),
):
    obj = get_object_or_404(queryset, uid=invitation_uid)
    obj.delete()


@invitation_incoming_router.post("/{invitation_uid}/accept/", status_code=status.HTTP_201_CREATED)
def incoming_accept(
    invitation_uid: str,
    data: CollectionInvitationAcceptIn,
    queryset: QuerySet = Depends(get_incoming_queryset),
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


@invitation_outgoing_router.post("/", status_code=status.HTTP_201_CREATED)
def outgoing_create(
    data: CollectionInvitationIn,
    request: Request,
    user: User = Depends(get_authenticated_user),
):
    collection = get_object_or_404(models.Collection.objects, uid=data.collection)
    to_user = get_object_or_404(
        get_user_queryset(User.objects.all(), CallbackContext(request.path_params)), username=data.username
    )

    context = Context(user, None)
    data.validate_db(context)

    if not is_collection_admin(collection, user):
        raise PermissionDenied("admin_access_required", "User is not an admin of this collection")

    member = collection.members.get(user=user)

    with transaction.atomic():
        try:
            ret = models.CollectionInvitation.objects.create(
                **data.dict(exclude={"collection", "username"}), user=to_user, fromMember=member
            )
        except IntegrityError:
            raise ValidationError("invitation_exists", "Invitation already exists")

    return MsgpackResponse(CollectionInvitationOut.from_orm(ret), status_code=status.HTTP_201_CREATED)


@invitation_outgoing_router.get("/", response_model=InvitationListResponse)
def outgoing_list(
    iterator: t.Optional[str] = None,
    limit: int = 50,
    queryset: QuerySet = Depends(get_outgoing_queryset),
):
    return list_common(queryset, iterator, limit)


@invitation_outgoing_router.delete("/{invitation_uid}/", status_code=status.HTTP_204_NO_CONTENT)
def outgoing_delete(
    invitation_uid: str,
    queryset: QuerySet = Depends(get_outgoing_queryset),
):
    obj = get_object_or_404(queryset, uid=invitation_uid)
    obj.delete()


@invitation_outgoing_router.get("/fetch_user_profile/", response_model=UserInfoOut)
def outgoing_fetch_user_profile(
    username: str,
    request: Request,
    user: User = Depends(get_authenticated_user),
):
    kwargs = {User.USERNAME_FIELD: username.lower()}
    user = get_object_or_404(get_user_queryset(User.objects.all(), CallbackContext(request.path_params)), **kwargs)
    user_info = get_object_or_404(models.UserInfo.objects.all(), owner=user)
    ret = UserInfoOut.from_orm(user_info)
    return MsgpackResponse(ret)
