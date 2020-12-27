from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.shortcuts import get_object_or_404
from fastapi import APIRouter, Request, Response, status

from django_etebase.utils import get_user_queryset, CallbackContext
from etebase_fastapi.authentication import SignupIn, signup_save
from etebase_fastapi.msgpack import MsgpackRoute

test_reset_view_router = APIRouter(route_class=MsgpackRoute)
User = get_user_model()


@test_reset_view_router.post("/reset/")
def reset(data: SignupIn, request: Request):
    # Only run when in DEBUG mode! It's only used for tests
    if not settings.DEBUG:
        return Response("Only allowed in debug mode.", status_code=status.HTTP_400_BAD_REQUEST)

    with transaction.atomic():
        user_queryset = get_user_queryset(User.objects.all(), CallbackContext(request.path_params))
        user = get_object_or_404(user_queryset, username=data.user.username)
        # Only allow test users for extra safety
        if not getattr(user, User.USERNAME_FIELD).startswith("test_user"):
            return Response("Endpoint not allowed for user.", status_code=status.HTTP_400_BAD_REQUEST)

        if hasattr(user, "userinfo"):
            user.userinfo.delete()
        signup_save(data, request)
        # Delete all of the journal data for this user for a clear test env
        user.collection_set.all().delete()
        user.collectionmember_set.all().delete()
        user.incoming_invitations.all().delete()

        # FIXME: also delete chunk files!!!

    return Response(status_code=status.HTTP_204_NO_CONTENT)
