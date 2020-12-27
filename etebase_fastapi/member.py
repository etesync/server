import typing as t

from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import QuerySet
from fastapi import Depends, status
from pydantic import BaseModel

from django_etebase import models
from .authentication import get_authenticated_user
from .msgpack import MsgpackResponse
from .utils import get_object_or_404
from .stoken_handler import filter_by_stoken_and_limit

from .collection import collection_router, get_collection

User = get_user_model()
default_queryset: QuerySet = models.CollectionMember.objects.all()


def get_queryset(collection: models.Collection = Depends(get_collection)) -> QuerySet:
    return default_queryset.filter(collection=collection)


def get_member(username: str, queryset: QuerySet = Depends(get_queryset)) -> QuerySet:
    return get_object_or_404(queryset, user__username__iexact=username)


class CollectionMemberModifyAccessLevelIn(BaseModel):
    accessLevel: models.AccessLevels


class CollectionMemberOut(BaseModel):
    username: str
    accessLevel: models.AccessLevels

    class Config:
        orm_mode = True

    @classmethod
    def from_orm(cls: t.Type["CollectionMemberOut"], obj: models.CollectionMember) -> "CollectionMemberOut":
        return cls(username=obj.user.username, accessLevel=obj.accessLevel)


class MemberListResponse(BaseModel):
    data: t.List[CollectionMemberOut]
    iterator: t.Optional[str]
    done: bool


@collection_router.get("/{collection_uid}/member/", response_model=MemberListResponse)
def member_list(
    iterator: t.Optional[str] = None,
    limit: int = 50,
    queryset: QuerySet = Depends(get_queryset),
):
    queryset = queryset.order_by("id")
    result, new_stoken_obj, done = filter_by_stoken_and_limit(
        iterator, limit, queryset, models.CollectionMember.stoken_annotation
    )
    new_stoken = new_stoken_obj and new_stoken_obj.uid

    ret = MemberListResponse(
        data=[CollectionMemberOut.from_orm(item) for item in result],
        iterator=new_stoken,
        done=done,
    )
    return MsgpackResponse(ret)


@collection_router.delete("/{collection_uid}/member/{username}/", status_code=status.HTTP_204_NO_CONTENT)
def member_delete(
    obj: models.CollectionMember = Depends(get_member),
):
    obj.revoke()


@collection_router.patch("/{collection_uid}/member/{username}/", status_code=status.HTTP_204_NO_CONTENT)
def member_patch(
    data: CollectionMemberModifyAccessLevelIn,
    instance: models.CollectionMember = Depends(get_member),
):
    with transaction.atomic():
        # We only allow updating accessLevel
        if instance.accessLevel != data.accessLevel:
            instance.stoken = models.Stoken.objects.create()
            instance.accessLevel = data.accessLevel
            instance.save()


@collection_router.post("/{collection_uid}/member/leave/", status_code=status.HTTP_204_NO_CONTENT)
def member_leave(user: User = Depends(get_authenticated_user), collection: models.Collection = Depends(get_collection)):
    obj = get_object_or_404(collection.members, user=user)
    obj.revoke()
