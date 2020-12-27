import dataclasses
import typing as t

from fastapi import status, Query

from django.db.models import QuerySet
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model

from django_etebase.models import AccessLevels

from .exceptions import ValidationError

User = get_user_model()

Prefetch = t.Literal["auto", "medium"]
PrefetchQuery = Query(default="auto")


@dataclasses.dataclass
class Context:
    user: t.Optional[User]
    prefetch: t.Optional[Prefetch]


def get_object_or_404(queryset: QuerySet, **kwargs):
    try:
        return queryset.get(**kwargs)
    except ObjectDoesNotExist as e:
        raise ValidationError("does_not_exist", str(e), status_code=status.HTTP_404_NOT_FOUND)


def is_collection_admin(collection, user):
    member = collection.members.filter(user=user).first()
    return (member is not None) and (member.accessLevel == AccessLevels.ADMIN)
