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
from django.core.exceptions import PermissionDenied
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

from . import app_settings, permissions
from .models import (
        Collection,
        CollectionItem,
        CollectionItemRevision,
        CollectionMember,
        CollectionInvitation,
        Stoken,
        UserInfo,
    )
from .serializers import (
        b64encode,
        AuthenticationSignupSerializer,
        AuthenticationLoginChallengeSerializer,
        AuthenticationLoginSerializer,
        AuthenticationLoginInnerSerializer,
        CollectionSerializer,
        CollectionItemSerializer,
        CollectionItemBulkGetSerializer,
        CollectionItemDepSerializer,
        CollectionItemRevisionSerializer,
        CollectionItemChunkSerializer,
        CollectionMemberSerializer,
        CollectionInvitationSerializer,
        InvitationAcceptSerializer,
        UserInfoPubkeySerializer,
        UserSerializer,
    )


User = get_user_model()


class BaseViewSet(viewsets.ModelViewSet):
    authentication_classes = tuple(app_settings.API_AUTHENTICATORS)
    permission_classes = tuple(app_settings.API_PERMISSIONS)
    cstoken_id_field = None

    def get_serializer_class(self):
        serializer_class = self.serializer_class

        if self.request.method == 'PUT':
            serializer_class = getattr(self, 'serializer_update_class', serializer_class)

        return serializer_class

    def get_collection_queryset(self, queryset=Collection.objects):
        user = self.request.user
        return queryset.filter(members__user=user)

    def get_cstoken_obj(self, request):
        cstoken = request.GET.get('cstoken', None)

        if cstoken is not None:
            return get_object_or_404(Stoken.objects.all(), uid=cstoken)

        return None

    def filter_by_cstoken(self, request, queryset):
        cstoken_id_field = self.cstoken_id_field + '__id'

        cstoken_rev = self.get_cstoken_obj(request)
        if cstoken_rev is not None:
            filter_by = {cstoken_id_field + '__gt': cstoken_rev.id}
            queryset = queryset.filter(**filter_by)

        return queryset, cstoken_rev

    def get_queryset_cstoken(self, queryset):
        cstoken_id_field = self.cstoken_id_field + '__id'

        new_cstoken_id = queryset.aggregate(cstoken_id=Max(cstoken_id_field))['cstoken_id']
        new_cstoken = new_cstoken_id and Stoken.objects.get(id=new_cstoken_id).uid

        return queryset, new_cstoken

    def filter_by_cstoken_and_limit(self, request, queryset):
        limit = int(request.GET.get('limit', 50))

        queryset, cstoken_rev = self.filter_by_cstoken(request, queryset)
        cstoken = cstoken_rev.uid if cstoken_rev is not None else None

        queryset = queryset[:limit]
        queryset, new_cstoken = self.get_queryset_cstoken(queryset)
        new_cstoken = new_cstoken or cstoken

        return queryset, new_cstoken


class CollectionViewSet(BaseViewSet):
    allowed_methods = ['GET', 'POST', 'DELETE']
    permission_classes = BaseViewSet.permission_classes
    queryset = Collection.objects.all()
    serializer_class = CollectionSerializer
    lookup_field = 'uid'
    cstoken_id_field = 'items__revisions__stoken'

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

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response({})

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
        queryset, new_cstoken = self.filter_by_cstoken_and_limit(request, queryset)

        serializer = self.serializer_class(queryset, context=self.get_serializer_context(), many=True)

        ret = {
            'data': serializer.data,
            'cstoken': new_cstoken,
        }
        return Response(ret)


class CollectionItemViewSet(BaseViewSet):
    allowed_methods = ['GET', 'POST', 'PUT']
    permission_classes = BaseViewSet.permission_classes
    queryset = CollectionItem.objects.all()
    serializer_class = CollectionItemSerializer
    lookup_field = 'uid'
    cstoken_id_field = 'revisions__stoken'

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

    def update(self, request, collection_uid=None, uid=None):
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def partial_update(self, request, collection_uid=None, uid=None):
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def list(self, request, collection_uid=None):
        queryset = self.get_queryset()
        queryset, new_cstoken = self.filter_by_cstoken_and_limit(request, queryset)

        serializer = self.serializer_class(queryset, context=self.get_serializer_context(), many=True)

        ret = {
            'data': serializer.data,
            'cstoken': new_cstoken,
        }
        return Response(ret)

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

    # FIXME: rename to something consistent with what the clients have - maybe list_updates?
    @action_decorator(detail=False, methods=['POST'])
    def fetch_updates(self, request, collection_uid=None):
        queryset = self.get_queryset()

        serializer = CollectionItemBulkGetSerializer(data=request.data, many=True)
        if serializer.is_valid():
            # FIXME: make configurable?
            item_limit = 200

            if len(serializer.validated_data) > item_limit:
                content = {'code': 'too_many_items',
                           'detail': 'Request has too many items. Limit: {}'. format(item_limit)}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)

            queryset, cstoken_rev = self.filter_by_cstoken(request, queryset)

            uids, stokens = zip(*[(item['uid'], item.get('stoken')) for item in serializer.validated_data])
            revs = CollectionItemRevision.objects.filter(uid__in=stokens, current=True)
            queryset = queryset.filter(uid__in=uids).exclude(revisions__in=revs)

            queryset, new_cstoken = self.get_queryset_cstoken(queryset)
            cstoken = cstoken_rev and cstoken_rev.uid
            new_cstoken = new_cstoken or cstoken

            serializer = self.get_serializer_class()(queryset, context=self.get_serializer_context(), many=True)

            ret = {
                'data': serializer.data,
                'cstoken': new_cstoken,
            }
            return Response(ret)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action_decorator(detail=False, methods=['POST'])
    def batch(self, request, collection_uid=None):
        cstoken = request.GET.get('cstoken', None)
        collection_object = get_object_or_404(self.get_collection_queryset(Collection.objects), uid=collection_uid)

        if cstoken is not None and cstoken != collection_object.cstoken:
            content = {'code': 'stale_cstoken', 'detail': 'CSToken is too old'}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)

        items = request.data.get('items')
        context = self.get_serializer_context()
        serializer = self.get_serializer_class()(data=items, context=context, many=True)

        if serializer.is_valid():
            try:
                with transaction.atomic():
                    items = serializer.save(collection=collection_object)
            except IntegrityError:
                # FIXME: should return the items with a bad token (including deps) so we don't have to fetch them after
                content = {'code': 'integrity_error'}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)

            ret = {
            }
            return Response(ret, status=status.HTTP_200_OK)

        return Response(
            {
                "items": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST)

    @action_decorator(detail=False, methods=['POST'])
    def transaction(self, request, collection_uid=None):
        cstoken = request.GET.get('cstoken', None)
        collection_object = get_object_or_404(self.get_collection_queryset(Collection.objects), uid=collection_uid)

        if cstoken is not None and cstoken != collection_object.cstoken:
            content = {'code': 'stale_cstoken', 'detail': 'CSToken is too old'}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)

        items = request.data.get('items')
        deps = request.data.get('deps', None)
        # FIXME: It should just be one serializer
        context = self.get_serializer_context()
        context.update({'validate_stoken': True})
        serializer = self.get_serializer_class()(data=items, context=context, many=True)
        deps_serializer = CollectionItemDepSerializer(data=deps, context=context, many=True)

        ser_valid = serializer.is_valid()
        deps_ser_valid = (deps is None or deps_serializer.is_valid())
        if ser_valid and deps_ser_valid:
            try:
                with transaction.atomic():
                    items = serializer.save(collection=collection_object)
            except IntegrityError:
                # FIXME: should return the items with a bad token (including deps) so we don't have to fetch them after
                content = {'code': 'integrity_error'}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)

            ret = {
            }
            return Response(ret, status=status.HTTP_200_OK)

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


class CollectionMemberViewSet(BaseViewSet):
    allowed_methods = ['GET', 'PUT', 'DELETE']
    permission_classes = BaseViewSet.permission_classes + (permissions.IsCollectionAdmin, )
    queryset = CollectionMember.objects.all()
    serializer_class = CollectionMemberSerializer
    lookup_field = 'user__' + User.USERNAME_FIELD
    lookup_url_kwarg = 'username'

    # FIXME: need to make sure that there's always an admin, and maybe also don't let an owner remove adm access
    # (if we want to transfer, we need to do that specifically)

    def get_queryset(self, queryset=None):
        collection_uid = self.kwargs['collection_uid']
        try:
            collection = self.get_collection_queryset(Collection.objects).get(uid=collection_uid)
        except Collection.DoesNotExist:
            raise Http404('Collection does not exist')

        if queryset is None:
            queryset = type(self).queryset

        return queryset.filter(collection=collection)

    def create(self, request):
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)


class InvitationOutgoingViewSet(BaseViewSet):
    allowed_methods = ['GET', 'POST', 'PUT', 'DELETE']
    permission_classes = BaseViewSet.permission_classes
    queryset = CollectionInvitation.objects.all()
    serializer_class = CollectionInvitationSerializer
    lookup_field = 'uid'
    lookup_url_kwarg = 'invitation_uid'

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({'request': self.request})
        return context

    def get_queryset(self, queryset=None):
        if queryset is None:
            queryset = type(self).queryset

        return queryset.filter(fromMember__user=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context=self.get_serializer_context())
        if serializer.is_valid():
            collection_uid = serializer.validated_data.get('collection', {}).get('uid')

            try:
                collection = self.get_collection_queryset(Collection.objects).get(uid=collection_uid)
            except Collection.DoesNotExist:
                raise Http404('Collection does not exist')

            if not permissions.is_collection_admin(collection, request.user):
                raise PermissionDenied('User is not an admin of this collection')

            serializer.save(collection=collection)

            return Response({}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action_decorator(detail=False, allowed_methods=['GET'], methods=['GET'])
    def fetch_user_profile(self, request):
        username = request.GET.get('username')
        kwargs = {'owner__' + User.USERNAME_FIELD: username}
        user_info = get_object_or_404(UserInfo.objects.all(), **kwargs)
        serializer = UserInfoPubkeySerializer(user_info)
        return Response(serializer.data)


class InvitationIncomingViewSet(BaseViewSet):
    allowed_methods = ['GET', 'DELETE']
    queryset = CollectionInvitation.objects.all()
    serializer_class = CollectionInvitationSerializer
    lookup_field = 'uid'
    lookup_url_kwarg = 'invitation_uid'

    def get_queryset(self, queryset=None):
        if queryset is None:
            queryset = type(self).queryset

        return queryset.filter(user=self.request.user)

    @action_decorator(detail=True, allowed_methods=['POST'], methods=['POST'])
    def accept(self, request, invitation_uid=None):
        invitation = get_object_or_404(self.get_queryset(), uid=invitation_uid)
        context = self.get_serializer_context()
        context.update({'invitation': invitation})

        serializer = InvitationAcceptSerializer(data=request.data, context=context)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_201_CREATED)


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
                elif not settings.DEBUG and host != request.get_host():
                    detail = 'Found wrong host name. Got: "{}" expected: "{}"'.format(host, request.get_host())
                    content = {'code': 'wrong_host', 'detail': detail}
                    return Response(content, status=status.HTTP_400_BAD_REQUEST)

                verify_key = nacl.signing.VerifyKey(user.userinfo.loginPubkey, encoder=nacl.encoding.RawEncoder)
                verify_key.verify(response_raw, signature)

                data = self.login_response_data(user)
                return Response(data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action_decorator(detail=False, methods=['POST'])
    def logout(self, request):
        # FIXME: expire the token - we need better token handling - using knox? Something else?
        return Response({}, status=status.HTTP_200_OK)


class TestAuthenticationViewSet(viewsets.ViewSet):
    authentication_classes = BaseViewSet.authentication_classes
    permission_classes = BaseViewSet.permission_classes
    allowed_methods = ['POST']

    def list(self, request):
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    @action_decorator(detail=False, methods=['POST'])
    def reset(self, request, *args, **kwargs):
        # Only run when in DEBUG mode! It's only used for tests
        if not settings.DEBUG:
            return HttpResponseBadRequest("Only allowed in debug mode.")

        # Only allow local users, for extra safety
        if not getattr(request.user, User.EMAIL_FIELD).endswith('@localhost'):
            return HttpResponseBadRequest("Endpoint not allowed for user.")

        # Delete all of the journal data for this user for a clear test env
        request.user.collection_set.all().delete()
        request.user.incoming_invitations.all().delete()

        # FIXME: also delete chunk files!!!

        return HttpResponse()
