import typing as t
from dataclasses import dataclass

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied

from . import app_settings


User = get_user_model()


@dataclass
class CallbackContext:
    """Class for passing extra context to callbacks"""

    url_kwargs: t.Dict[str, t.Any]
    user: t.Optional[User] = None


def get_user_queryset(queryset, context: CallbackContext):
    custom_func = app_settings.GET_USER_QUERYSET_FUNC
    if custom_func is not None:
        return custom_func(queryset, context)
    return queryset


def create_user(context: CallbackContext, *args, **kwargs):
    custom_func = app_settings.CREATE_USER_FUNC
    if custom_func is not None:
        return custom_func(*args, **kwargs)
    return User.objects.create_user(*args, **kwargs)


def create_user_blocked(*args, **kwargs):
    raise PermissionDenied("Signup is disabled for this server. Please refer to the README for more information.")
