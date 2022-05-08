"""
FIXME: this whole function is a hack around the django db limitations due to how db connections are cached and cleaned.
Essentially django assumes there's the django request dispatcher to automatically clean up after the ORM.
"""
import typing as t
from functools import wraps

from django.db import close_old_connections, reset_queries


def django_db_cleanup():
    reset_queries()
    close_old_connections()


def django_db_cleanup_decorator(func: t.Callable[..., t.Any]):
    from inspect import iscoroutinefunction

    if iscoroutinefunction(func):
        return func

    @wraps(func)
    def wrapper(*args, **kwargs):
        django_db_cleanup()
        return func(*args, **kwargs)

    return wrapper
