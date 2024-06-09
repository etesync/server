import base64
import dataclasses
import typing as t

import msgpack
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Model, QuerySet
from fastapi import Depends, Query, status
from pydantic import BaseModel as PyBaseModel
from typing_extensions import Literal

from etebase_server.django import app_settings
from etebase_server.django.models import AccessLevels
from etebase_server.myauth.models import UserType, get_typed_user_model

from .exceptions import HttpError, HttpErrorOut

User = get_typed_user_model()

Prefetch = Literal["auto", "medium"]
PrefetchQuery = Query(default="auto")


T = t.TypeVar("T", bound=Model, covariant=True)


class BaseModel(PyBaseModel):
    pass


@dataclasses.dataclass
class Context:
    user: t.Optional[UserType]
    prefetch: t.Optional[Prefetch]


def get_object_or_404(queryset: QuerySet[T], **kwargs) -> T:
    try:
        return queryset.get(**kwargs)
    except ObjectDoesNotExist as e:
        raise HttpError("does_not_exist", str(e), status_code=status.HTTP_404_NOT_FOUND)


def is_collection_admin(collection, user):
    member = collection.members.filter(user=user).first()
    return (member is not None) and (member.accessLevel == AccessLevels.ADMIN)


def msgpack_encode(content) -> bytes:
    ret = msgpack.packb(content, use_bin_type=True)
    assert ret is not None
    return ret


def msgpack_decode(content: bytes):
    return msgpack.unpackb(content, raw=False)


def b64encode(value: bytes):
    return base64.urlsafe_b64encode(value).decode("ascii").strip("=")


def b64decode(data: str):
    data += "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data)


def get_user_username_email_kwargs(username: str):
    field_name = User.EMAIL_FIELD if "@" in username else User.USERNAME_FIELD
    return {field_name + "__iexact": username.lower()}


PERMISSIONS_READ = [Depends(x) for x in app_settings.API_PERMISSIONS_READ]
PERMISSIONS_READWRITE = PERMISSIONS_READ + [Depends(x) for x in app_settings.API_PERMISSIONS_WRITE]


response_model_dict = {"model": HttpErrorOut}
permission_responses: t.Dict[t.Union[int, str], t.Dict[str, t.Any]] = {
    401: response_model_dict,
    403: response_model_dict,
}
