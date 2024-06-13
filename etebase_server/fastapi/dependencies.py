import dataclasses

from django.db.models import QuerySet
from django.utils import timezone
from fastapi import Depends
from fastapi.security import APIKeyHeader

from etebase_server.django import models
from etebase_server.django.token_auth.models import AuthToken, get_default_expiry
from etebase_server.myauth.models import UserType, get_typed_user_model

from .db_hack import django_db_cleanup_decorator
from .exceptions import AuthenticationFailed

User = get_typed_user_model()
token_scheme = APIKeyHeader(name="Authorization")
AUTO_REFRESH = True
MIN_REFRESH_INTERVAL = 60


@dataclasses.dataclass(frozen=True)
class AuthData:
    user: UserType
    token: AuthToken


def __renew_token(auth_token: AuthToken):
    current_expiry = auth_token.expiry
    new_expiry = get_default_expiry()
    # Throttle refreshing of token to avoid db writes
    delta = (new_expiry - current_expiry).total_seconds()
    if delta > MIN_REFRESH_INTERVAL:
        auth_token.expiry = new_expiry
        auth_token.save(update_fields=("expiry",))


def __get_authenticated_user(api_token: str):
    api_token = api_token.split()[1]
    try:
        token: AuthToken = AuthToken.objects.select_related("user").get(key=api_token)
    except AuthToken.DoesNotExist:
        raise AuthenticationFailed(detail="Invalid token.")
    if not token.user.is_active:
        raise AuthenticationFailed(detail="User inactive or deleted.")

    if token.expiry is not None:
        if token.expiry < timezone.now():
            token.delete()
            raise AuthenticationFailed(detail="Invalid token.")

        if AUTO_REFRESH:
            __renew_token(token)

    return token.user, token


@django_db_cleanup_decorator
def get_auth_data(api_token: str = Depends(token_scheme)) -> AuthData:
    user, token = __get_authenticated_user(api_token)
    return AuthData(user, token)


@django_db_cleanup_decorator
def get_authenticated_user(api_token: str = Depends(token_scheme)) -> UserType:
    user, _ = __get_authenticated_user(api_token)
    return user


@django_db_cleanup_decorator
def get_collection_queryset(user: UserType = Depends(get_authenticated_user)) -> QuerySet:
    default_queryset: QuerySet = models.Collection.objects.all()
    return default_queryset.filter(members__user=user)


@django_db_cleanup_decorator
def get_collection(collection_uid: str, queryset: QuerySet = Depends(get_collection_queryset)) -> models.Collection:
    from .utils import get_object_or_404

    return get_object_or_404(queryset, uid=collection_uid)


@django_db_cleanup_decorator
def get_item_queryset(collection: models.Collection = Depends(get_collection)) -> QuerySet:
    default_item_queryset: QuerySet = models.CollectionItem.objects.all()
    # XXX Potentially add this for performance: .prefetch_related('revisions__chunks')
    queryset = default_item_queryset.filter(collection__pk=collection.pk, revisions__current=True)

    return queryset
