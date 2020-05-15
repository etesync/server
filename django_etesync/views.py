# Copyright © 2017 Tom Hacohen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, version 3.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import json

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction, IntegrityError
from django.db.models import Max
from django.http import HttpResponseBadRequest, HttpResponse, Http404
from django.shortcuts import get_object_or_404

from rest_framework import status
from rest_framework import viewsets
from rest_framework import parsers
from rest_framework.decorators import action as action_decorator
from rest_framework.response import Response
from rest_framework.authtoken.models import Token

import nacl.encoding
import nacl.signing
import nacl.secret
import nacl.hash

from . import app_settings
from .models import Collection, CollectionItem, CollectionItemRevision
from .serializers import (
        b64encode,
        AuthenticationSignupSerializer,
        AuthenticationLoginChallengeSerializer,
        AuthenticationLoginSerializer,
        AuthenticationLoginInnerSerializer,
        CollectionSerializer,
        CollectionItemSerializer,
        CollectionItemRevisionSerializer,
        CollectionItemChunkSerializer,
        UserSerializer,
    )


User = get_user_model()


class BaseViewSet(viewsets.ModelViewSet):
    authentication_classes = tuple(app_settings.API_AUTHENTICATORS)
    permission_classes = tuple(app_settings.API_PERMISSIONS)
    stoken_id_field = None

    def get_serializer_class(self):
        serializer_class = self.serializer_class

        if self.request.method == 'PUT':
            serializer_class = getattr(self, 'serializer_update_class', serializer_class)

        return serializer_class

    def get_collection_queryset(self, queryset=Collection.objects):
        user = self.request.user
        return queryset.filter(members__user=user)

    def filter_by_stoken_and_limit(self, request, queryset):
        stoken = request.GET.get('stoken', None)
        limit = int(request.GET.get('limit', 50))

        stoken_id_field = self.stoken_id_field + '__id'

        if stoken is not None:
            last_rev = get_object_or_404(CollectionItemRevision.objects.all(), uid=stoken)
            filter_by = {stoken_id_field + '__gt': last_rev.id}
            queryset = queryset.filter(**filter_by)

        new_stoken_id = queryset.aggregate(stoken_id=Max(stoken_id_field))['stoken_id']
        new_stoken = CollectionItemRevision.objects.get(id=new_stoken_id).uid if new_stoken_id is not None else stoken

        return queryset[:limit], new_stoken


class CollectionViewSet(BaseViewSet):
    allowed_methods = ['GET', 'POST', 'DELETE']
    permission_classes = BaseViewSet.permission_classes
    queryset = Collection.objects.all()
    serializer_class = CollectionSerializer
    lookup_field = 'uid'
    stoken_id_field = 'items__revisions'

    def get_queryset(self, queryset=None):
        if queryset is None:
            queryset = type(self).queryset
        return self.get_collection_queryset(queryset)

    def get_serializer_context(self):
        context = super().get_serializer_context()
        inline = 'inline' in self.request.query_params
        context.update({'request': self.request, 'inline': inline})
        return context

    def destroy(self, request, uid=None):
        # FIXME: implement
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def partial_update(self, request, uid=None):
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context=self.get_serializer_context())
        if serializer.is_valid():
            try:
                serializer.save(owner=self.request.user)
            except IntegrityError:
                content = {'code': 'integrity_error'}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)

            return Response({}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def list(self, request):
        queryset = self.get_queryset()
        queryset, new_stoken = self.filter_by_stoken_and_limit(request, queryset)

        serializer = self.serializer_class(queryset, context=self.get_serializer_context(), many=True)

        ret = {
            'data': serializer.data,
        }
        return Response(ret, headers={'X-EteSync-SToken': new_stoken})


class CollectionItemViewSet(BaseViewSet):
    allowed_methods = ['GET', 'POST', 'PUT']
    permission_classes = BaseViewSet.permission_classes
    queryset = CollectionItem.objects.all()
    serializer_class = CollectionItemSerializer
    lookup_field = 'uid'
    stoken_id_field = 'revisions'

    def get_queryset(self):
        collection_uid = self.kwargs['collection_uid']
        try:
            collection = self.get_collection_queryset(Collection.objects).get(uid=collection_uid)
        except Collection.DoesNotExist:
            raise Http404("Collection does not exist")
        # XXX Potentially add this for performance: .prefetch_related('revisions__chunks')
        queryset = type(self).queryset.filter(collection__pk=collection.pk,
                                              revisions__current=True,
                                              revisions__deleted=False)

        return queryset

    def get_serializer_context(self):
        context = super().get_serializer_context()
        inline = 'inline' in self.request.query_params
        context.update({'request': self.request, 'inline': inline})
        return context

    def create(self, request, collection_uid=None):
        collection_object = get_object_or_404(self.get_collection_queryset(Collection.objects), uid=collection_uid)

        # FIXME: change this to also support bulk update, or have another endpoint for that.
        # See https://www.django-rest-framework.org/api-guide/serializers/#customizing-multiple-update
        many = isinstance(request.data, list)
        serializer = self.serializer_class(data=request.data, many=many)
        if serializer.is_valid():
            try:
                serializer.save(collection=collection_object)
            except IntegrityError:
                content = {'code': 'integrity_error'}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)

            return Response({}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, collection_uid=None, uid=None):
        # We can't have destroy because we need to get data from the user (in the body) such as hmac.
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def partial_update(self, request, collection_uid=None, uid=None):
        # FIXME: implement, or should it be implemented elsewhere?
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def list(self, request, collection_uid=None):
        queryset = self.get_queryset()
        queryset, new_stoken = self.filter_by_stoken_and_limit(request, queryset)

        serializer = self.serializer_class(queryset, context=self.get_serializer_context(), many=True)

        ret = {
            'data': serializer.data,
        }
        return Response(ret, headers={'X-EteSync-SToken': new_stoken})

    @action_decorator(detail=True, methods=['GET'])
    def revision(self, request, collection_uid=None, uid=None):
        # FIXME: need pagination support
        col = get_object_or_404(self.get_collection_queryset(Collection.objects), uid=collection_uid)
        col_it = get_object_or_404(col.items, uid=uid)

        serializer = CollectionItemRevisionSerializer(col_it.revisions.order_by('-id'), many=True)
        ret = {
            'data': serializer.data,
        }
        return Response(ret)

    @action_decorator(detail=False, methods=['POST'])
    def bulk_get(self, request, collection_uid=None):
        queryset = self.get_queryset()

        if isinstance(request.data, list):
            queryset = queryset.filter(uid__in=request.data)

        queryset, new_stoken = self.filter_by_stoken_and_limit(request, queryset)

        serializer = self.get_serializer_class()(queryset, context=self.get_serializer_context(), many=True)

        ret = {
            'data': serializer.data,
        }
        return Response(ret, headers={'X-EteSync-SToken': new_stoken})

    @action_decorator(detail=False, methods=['POST'])
    def transaction(self, request, collection_uid=None):
        collection_object = get_object_or_404(self.get_collection_queryset(Collection.objects), uid=collection_uid)

        items = request.data.get('items')
        # FIXME: deps should actually be just pairs of uid and stoken
        deps = request.data.get('deps', None)
        serializer = self.get_serializer_class()(data=items, context=self.get_serializer_context(), many=True)
        deps_serializer = self.get_serializer_class()(data=deps, context=self.get_serializer_context(), many=True)
        if serializer.is_valid() and (deps is None or deps_serializer.is_valid()):
            try:
                with transaction.atomic():
                    collections = serializer.save(collection=collection_object)
            except IntegrityError:
                content = {'code': 'integrity_error'}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)

            ret = {
                "data": [collection.stoken for collection in collections],
            }
            return Response(ret, status=status.HTTP_201_CREATED)

        return Response(
            {
                "items": serializer.errors,
                "deps": deps_serializer.errors if deps is not None else [],
            },
            status=status.HTTP_400_BAD_REQUEST)


class CollectionItemChunkViewSet(viewsets.ViewSet):
    allowed_methods = ['GET', 'POST']
    parser_classes = (parsers.MultiPartParser, )
    authentication_classes = BaseViewSet.authentication_classes
    permission_classes = BaseViewSet.permission_classes
    serializer_class = CollectionItemChunkSerializer
    lookup_field = 'uid'

    def get_collection_queryset(self, queryset=Collection.objects):
        user = self.request.user
        return queryset.filter(members__user=user)

    def create(self, request, collection_uid=None, collection_item_uid=None):
        col = get_object_or_404(self.get_collection_queryset(), uid=collection_uid)
        col_it = get_object_or_404(col.items, uid=collection_item_uid)

        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            try:
                serializer.save(item=col_it)
            except IntegrityError:
                content = {'code': 'integrity_error'}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)

            return Response({}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action_decorator(detail=True, methods=['GET'])
    def download(self, request, collection_uid=None, collection_item_uid=None, uid=None):
        import os
        from django.views.static import serve

        col = get_object_or_404(self.get_collection_queryset(), uid=collection_uid)
        col_it = get_object_or_404(col.items, uid=collection_item_uid)
        chunk = get_object_or_404(col_it.chunks, uid=uid)

        filename = chunk.chunkFile.path
        dirname = os.path.dirname(filename)
        basename = os.path.basename(filename)

        # FIXME: DO NOT USE! Use django-send file or etc instead.
        return serve(request, basename, dirname)


class AuthenticationViewSet(viewsets.ViewSet):
    allowed_methods = ['POST']

    def get_encryption_key(self, salt):
        key = nacl.hash.blake2b(settings.SECRET_KEY.encode(), encoder=nacl.encoding.RawEncoder)
        return nacl.hash.blake2b(b'', key=key, salt=salt[:nacl.hash.BLAKE2B_SALTBYTES], person=b'etesync-auth',
                                 encoder=nacl.encoding.RawEncoder)

    def get_queryset(self):
        return User.objects.all()

    def login_response_data(self, user):
        return {
            'token': Token.objects.get_or_create(user=user)[0].key,
            'user': UserSerializer(user).data,
        }

    def list(self, request):
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    @action_decorator(detail=False, methods=['POST'])
    def signup(self, request):
        serializer = AuthenticationSignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            data = self.login_response_data(user)
            return Response(data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_login_user(self, serializer):
        username = serializer.validated_data.get('username')
        email = serializer.validated_data.get('email')
        if username:
            kwargs = {User.USERNAME_FIELD: username}
            user = get_object_or_404(self.get_queryset(), **kwargs)
        elif email:
            kwargs = {User.EMAIL_FIELD: email}
            user = get_object_or_404(self.get_queryset(), **kwargs)

        return user

    @action_decorator(detail=False, methods=['POST'])
    def login_challenge(self, request):
        from datetime import datetime

        serializer = AuthenticationLoginChallengeSerializer(data=request.data)
        if serializer.is_valid():
            user = self.get_login_user(serializer)

            salt = user.userinfo.salt
            enc_key = self.get_encryption_key(salt)
            box = nacl.secret.SecretBox(enc_key)

            challenge_data = {
                "timestamp": int(datetime.now().timestamp()),
                "userId": user.id,
            }
            challenge = box.encrypt(json.dumps(
                challenge_data, separators=(',', ':')).encode(), encoder=nacl.encoding.RawEncoder)

            ret = {
                "salt": b64encode(salt),
                "challenge": b64encode(challenge),
                "version": user.userinfo.version,
            }
            return Response(ret, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action_decorator(detail=False, methods=['POST'])
    def login(self, request):
        from datetime import datetime

        outer_serializer = AuthenticationLoginSerializer(data=request.data)
        if outer_serializer.is_valid():
            response_raw = outer_serializer.validated_data['response']
            response = json.loads(response_raw.decode())
            signature = outer_serializer.validated_data['signature']

            serializer = AuthenticationLoginInnerSerializer(data=response, context={'host': request.get_host()})
            if serializer.is_valid():
                user = self.get_login_user(serializer)
                host = serializer.validated_data['host']
                challenge = serializer.validated_data['challenge']

                salt = user.userinfo.salt
                enc_key = self.get_encryption_key(salt)
                box = nacl.secret.SecretBox(enc_key)

                challenge_data = json.loads(box.decrypt(challenge).decode())
                now = int(datetime.now().timestamp())
                if now - challenge_data['timestamp'] > app_settings.CHALLENGE_VALID_SECONDS:
                    content = {'code': 'challenge_expired', 'detail': 'Login challange has expired'}
                    return Response(content, status=status.HTTP_400_BAD_REQUEST)
                elif challenge_data['userId'] != user.id:
                    content = {'code': 'wrong_user', 'detail': 'This challenge is for the wrong user'}
                    return Response(content, status=status.HTTP_400_BAD_REQUEST)
                elif host != request.get_host():
                    detail = 'Found wrong host name. Got: "{}" expected: "{}"'.format(host, request.get_host())
                    content = {'code': 'wrong_host', 'detail': detail}
                    return Response(content, status=status.HTTP_400_BAD_REQUEST)

                verify_key = nacl.signing.VerifyKey(user.userinfo.pubkey, encoder=nacl.encoding.RawEncoder)
                verify_key.verify(response_raw, signature)

                data = self.login_response_data(user)
                return Response(data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action_decorator(detail=False, methods=['POST'])
    def logout(self, request):
        # FIXME: expire the token - we need better token handling - using knox? Something else?
        return Response({}, status=status.HTTP_400_BAD_REQUEST)


class ResetViewSet(BaseViewSet):
    allowed_methods = ['POST']

    def post(self, request, *args, **kwargs):
        # Only run when in DEBUG mode! It's only used for tests
        if not settings.DEBUG:
            return HttpResponseBadRequest("Only allowed in debug mode.")

        # Only allow local users, for extra safety
        if not getattr(request.user, User.USERNAME_FIELD).endswith('@localhost'):
            return HttpResponseBadRequest("Endpoint not allowed for user.")

        # Delete all of the journal data for this user for a clear test env
        request.user.collection_set.all().delete()

        # FIXME: also delete chunk files!!!

        return HttpResponse()


reset = ResetViewSet.as_view({'post': 'post'})
