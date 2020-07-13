from django.contrib.auth import get_user_model
from . import app_settings


User = get_user_model()


def get_user_queryset(queryset, view):
    custom_func = app_settings.GET_USER_QUERYSET_FUNC
    if custom_func is not None:
        return custom_func(queryset, view)
    return queryset


def create_user(*args, **kwargs):
    custom_func = app_settings.CREATE_USER_FUNC
    if custom_func is not None:
        return custom_func(*args, **kwargs)
    _ = kwargs.pop('view')
    return User.objects.create_user(*args, **kwargs)
