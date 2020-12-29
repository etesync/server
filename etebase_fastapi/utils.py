import dataclasses
import typing as t
import msgpack
import base64

from fastapi import status, Query, Depends
from pydantic import BaseModel as PyBaseModel

from django.db.models import Model, QuerySet
from django.core.exceptions import ObjectDoesNotExist

from django_etebase import app_settings
from django_etebase.models import AccessLevels
from myauth.models import UserType, get_typed_user_model

from .exceptions import HttpError, HttpErrorOut

User = get_typed_user_model()

Prefetch = t.Literal["auto", "medium"]
PrefetchQuery = Query(default="auto")


T = t.TypeVar("T", bound=Model, covariant=True)


class BaseModel(PyBaseModel):
    class Config:
        json_encoders = {
            bytes: lambda x: x,
        }


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


def msgpack_encode(content):
    ret = msgpack.packb(content, use_bin_type=True)
    assert ret is not None
    return ret


def msgpack_decode(content):
    return msgpack.unpackb(content, raw=False)


def b64encode(value):
    return base64.urlsafe_b64encode(value).decode("ascii").strip("=")


def b64decode(data):
    data += "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data)


PERMISSIONS_READ = [Depends(x) for x in app_settings.API_PERMISSIONS_READ]
PERMISSIONS_READWRITE = PERMISSIONS_READ + [Depends(x) for x in app_settings.API_PERMISSIONS_WRITE]


response_model_dict = {"model": HttpErrorOut}
permission_responses: t.Dict[t.Union[int, str], t.Dict[str, t.Any]] = {
    401: response_model_dict,
    403: response_model_dict,
}
