import typing as t

from django.contrib.auth import get_user_model
from django.db.models import QuerySet
from fastapi import Depends, status
from pydantic import BaseModel

from django_etebase import models
from .authentication import get_authenticated_user
from .msgpack import MsgpackResponse
from .utils import get_object_or_404
from .stoken_handler import filter_by_stoken_and_limit

from .collection import collection_router, get_collection_queryset

User = get_user_model()
default_queryset: QuerySet = models.CollectionMember.objects.all()


def get_queryset(user: User, collection_uid: str, queryset=default_queryset) -> t.Tuple[models.Collection, QuerySet]:
    collection = get_object_or_404(get_collection_queryset(user, models.Collection.objects), uid=collection_uid)
    return collection, queryset.filter(collection=collection)


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
    collection_uid: str,
    iterator: t.Optional[str] = None,
    limit: int = 50,
    user: User = Depends(get_authenticated_user),
):
    _, queryset = get_queryset(user, collection_uid)
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
    collection_uid: str,
    username: str,
    user: User = Depends(get_authenticated_user),
):
    _, queryset = get_queryset(user, collection_uid)
    obj = get_object_or_404(queryset, user__username__iexact=username)
    obj.revoke()


@collection_router.post("/{collection_uid}/member/leave/", status_code=status.HTTP_204_NO_CONTENT)
def member_leave(
    collection_uid: str,
    user: User = Depends(get_authenticated_user),
):
    collection, _ = get_queryset(user, collection_uid)
    obj = get_object_or_404(collection.members, user=user)
    obj.revoke()
