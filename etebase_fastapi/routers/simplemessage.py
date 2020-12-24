import typing as t

from django.db import transaction, IntegrityError
from django.db.models import QuerySet
from fastapi import APIRouter, Depends, status, Request

from django_etebase import models
from django_etebase.utils import get_user_queryset, CallbackContext
from myauth.models import UserType, get_typed_user_model
from .authentication import get_authenticated_user
from ..msgpack import MsgpackRoute
from ..exceptions import HttpError
from ..utils import (
    get_object_or_404,
    Context,
    BaseModel,
    permission_responses,
    PERMISSIONS_READ,
    PERMISSIONS_READWRITE,
)

User = get_typed_user_model()
simplemessage_router = APIRouter(route_class=MsgpackRoute, responses=permission_responses)
SimpleMessageQuerySet = QuerySet[models.SimpleMessage]
default_queryset: SimpleMessageQuerySet = models.SimpleMessage.objects.all()


def get_queryset(user: UserType = Depends(get_authenticated_user)) -> SimpleMessageQuerySet:
    return default_queryset.filter(toUser=user)


class SimpleMessageCommon(BaseModel):
    uid: str
    version: int
    toUsername: str
    content: bytes


class SimpleMessageIn(SimpleMessageCommon):
    def validate_db(self, context: Context):
        user = context.user
        if user is not None and (user.username == self.toUsername.lower()):
            raise HttpError("no_self_invite", "Inviting yourself is not allowed")


class SimpleMessageOut(SimpleMessageCommon):
    fromUsername: str
    fromPubkey: bytes

    class Config:
        orm_mode = True

    @classmethod
    def from_orm(cls: t.Type["SimpleMessageOut"], obj: models.SimpleMessage) -> "SimpleMessageOut":
        return cls(
            uid=obj.uid,
            version=obj.version,
            toUsername=obj.toUser.username,
            fromUsername=obj.fromUser.username,
            fromPubkey=bytes(obj.fromUser.userinfo.pubkey),
            content=bytes(obj.content),
        )


class SimpleMessageListResponse(BaseModel):
    data: t.List[SimpleMessageOut]
    iterator: t.Optional[str]
    done: bool


@simplemessage_router.get(
    "/",
    response_model=SimpleMessageListResponse,
    dependencies=[Depends(get_authenticated_user), *PERMISSIONS_READ],
)
def simplemessage_list(
    iterator: t.Optional[str] = None,
    limit: int = 50,
    queryset: SimpleMessageQuerySet = Depends(get_queryset),
):
    queryset = queryset.order_by("id")

    if iterator is not None:
        iterator_obj = get_object_or_404(queryset, uid=iterator)
        queryset = queryset.filter(id__lt=iterator_obj.id)

    result = list(queryset[: limit + 1])
    if len(result) < limit + 1:
        done = True
    else:
        done = False
        result = result[:-1]

    ret_data = [SimpleMessageOut.from_orm(revision) for revision in result]
    iterator = ret_data[-1].uid if len(result) > 0 else None

    return SimpleMessageListResponse(
        data=ret_data,
        iterator=iterator,
        done=done,
    )


@simplemessage_router.get(
    "/{message_uid}/",
    response_model=SimpleMessageListResponse,
    dependencies=PERMISSIONS_READ,
)
def simplemessage_get(
    message_uid: str,
    queryset: SimpleMessageQuerySet = Depends(get_queryset),
):
    obj = get_object_or_404(queryset, uid=message_uid)
    return SimpleMessageOut.from_orm(obj)


@simplemessage_router.delete(
    "/{message_uid}/",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=PERMISSIONS_READWRITE,
)
def simplemessage_delete(
    message_uid: str,
    queryset: SimpleMessageQuerySet = Depends(get_queryset),
):
    obj = get_object_or_404(queryset, uid=message_uid)
    obj.delete()


@simplemessage_router.post("/", status_code=status.HTTP_201_CREATED, dependencies=PERMISSIONS_READWRITE)
def simplemessage_create(
    data: SimpleMessageIn,
    request: Request,
    user: UserType = Depends(get_authenticated_user),
):
    to_user = get_object_or_404(
        get_user_queryset(User.objects.all(), CallbackContext(request.path_params)), username=data.toUsername
    )
    with transaction.atomic():
        try:
            models.SimpleMessage.objects.create(**data.dict(exclude={"toUsername"}), toUser=to_user, fromUser=user)
        except IntegrityError:
            raise HttpError(
                "unique_uid", "SimpleMessage with this uid already exists", status_code=status.HTTP_409_CONFLICT
            )
