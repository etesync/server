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
from functools import reduce

from django.conf import settings
from django.contrib.auth import get_user_model, user_logged_in, user_logged_out
from django.core.exceptions import PermissionDenied
from django.db import transaction, IntegrityError
from django.db.models import Max, Q
from django.http import HttpResponseBadRequest, HttpResponse, Http404
from django.shortcuts import get_object_or_404

from rest_framework import status
from rest_framework import viewsets
from rest_framework import parsers
from rest_framework.decorators import action as action_decorator
from rest_framework.response import Response

import nacl.encoding
import nacl.signing
import nacl.secret
import nacl.hash

from .token_auth.models import AuthToken

from . import app_settings, permissions
from .models import (
        Collection,
        CollectionItem,
        CollectionItemRevision,
        CollectionMember,
        CollectionMemberRemoved,
        CollectionInvitation,
        Stoken,
        UserInfo,
    )
from .serializers import (
        b64encode,
        AuthenticationChangePasswordInnerSerializer,
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
    stoken_id_fields = None

    def get_serializer_class(self):
        serializer_class = self.serializer_class

        if self.request.method == 'PUT':
            serializer_class = getattr(self, 'serializer_update_class', serializer_class)

        return serializer_class

    def get_collection_queryset(self, queryset=Collection.objects):
        user = self.request.user
        return queryset.filter(members__user=user)

    def get_stoken_obj_id(self, request):
        return request.GET.get('stoken', None)

    def get_stoken_obj(self, request):
        stoken = self.get_stoken_obj_id(request)

        if stoken is not None:
            return get_object_or_404(Stoken.objects.all(), uid=stoken)

        return None

    def filter_by_stoken(self, request, queryset):
        stoken_rev = self.get_stoken_obj(request)
        if stoken_rev is not None:
            filter_by_map = map(lambda x: Q(**{x + '__gt': stoken_rev.id}), self.stoken_id_fields)
            filter_by = reduce(lambda x, y: x | y, filter_by_map)
            queryset = queryset.filter(filter_by).distinct()

        return queryset, stoken_rev

    def get_queryset_stoken(self, queryset):
        aggr_field_names = ['max_{}'.format(i) for i, x in enumerate(self.stoken_id_fields)]
        aggr_fields = {name: Max(field) for name, field in zip(aggr_field_names, self.stoken_id_fields)}
        aggr = queryset.annotate(**aggr_fields).values(*aggr_field_names)
        # FIXME: we are doing it in python instead of SQL because I just couldn't get aggregate to work over the
        # annotated values. This should probably be fixed as it could be quite slow
        maxid = -1
        for row in aggr:
            rowmaxid = max(map(lambda x: x or -1, row.values()))
            maxid = max(maxid, rowmaxid)
        new_stoken = (maxid >= 0) and Stoken.objects.get(id=maxid).uid

        return queryset, new_stoken

    def filter_by_stoken_and_limit(self, request, queryset):
        limit = int(request.GET.get('limit', 50))

        queryset, stoken_rev = self.filter_by_stoken(request, queryset)
        stoken = stoken_rev.uid if stoken_rev is not None else None

        queryset = queryset[:limit]
        queryset, new_stoken = self.get_queryset_stoken(queryset)
        new_stoken = new_stoken or stoken
        # This is not the most efficient way of implementing this, but it's good enough
        done = len(queryset) < limit

        return queryset, new_stoken, done

    # Change how our list works by default
    def list(self, request, collection_uid=None):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        ret = {
            'data': serializer.data,
            'done': True,  # we always return all the items, so it's always done
        }

        return Response(ret)


class CollectionViewSet(BaseViewSet):
    allowed_methods = ['GET', 'POST']
    permission_classes = BaseViewSet.permission_classes + (permissions.IsCollectionAdminOrReadOnly, )
    queryset = Collection.objects.all()
    serializer_class = CollectionSerializer
    lookup_field = 'main_item__uid'
    lookup_url_kwarg = 'uid'
    stoken_id_fields = ['items__revisions__stoken__id', 'members__stoken__id']

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
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
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
        queryset, new_stoken, done = self.filter_by_stoken_and_limit(request, queryset)

        serializer = self.get_serializer(queryset, many=True)

        ret = {
            'data': serializer.data,
            'stoken': new_stoken,
            'done': done,
        }

        stoken_obj = self.get_stoken_obj(request)
        if stoken_obj is not None:
            # FIXME: honour limit? (the limit should be combined for data and this because of stoken)
            remed = CollectionMemberRemoved.objects.filter(user=request.user, stoken__id__gt=stoken_obj.id) \
                .values_list('collection__main_item__uid', flat=True)
            if len(remed) > 0:
                ret['removedMemberships'] = [{'uid': x} for x in remed]

        return Response(ret)


class CollectionItemViewSet(BaseViewSet):
    allowed_methods = ['GET', 'POST', 'PUT']
    permission_classes = BaseViewSet.permission_classes + (permissions.HasWriteAccessOrReadOnly, )
    queryset = CollectionItem.objects.all()
    serializer_class = CollectionItemSerializer
    lookup_field = 'uid'
    stoken_id_fields = ['revisions__stoken__id']

    def get_queryset(self):
        collection_uid = self.kwargs['collection_uid']
        try:
            collection = self.get_collection_queryset(Collection.objects).get(main_item__uid=collection_uid)
        except Collection.DoesNotExist:
            raise Http404("Collection does not exist")
        # XXX Potentially add this for performance: .prefetch_related('revisions__chunks')
        queryset = type(self).queryset.filter(collection__pk=collection.pk,
                                              revisions__current=True)

        return queryset

    def get_serializer_context(self):
        context = super().get_serializer_context()
        inline = 'inline' in self.request.query_params
        context.update({'request': self.request, 'inline': inline})
        return context

    def create(self, request, collection_uid=None):
        # We create using batch and transaction
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def destroy(self, request, collection_uid=None, uid=None):
        # We can't have destroy because we need to get data from the user (in the body) such as hmac.
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def update(self, request, collection_uid=None, uid=None):
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def partial_update(self, request, collection_uid=None, uid=None):
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def list(self, request, collection_uid=None):
        queryset = self.get_queryset()

        if not self.request.query_params.get('withCollection', False):
            queryset = queryset.filter(parent__isnull=True)

        queryset, new_stoken, done = self.filter_by_stoken_and_limit(request, queryset)

        serializer = self.get_serializer(queryset, many=True)

        ret = {
            'data': serializer.data,
            'stoken': new_stoken,
            'done': done,
        }
        return Response(ret)

    @action_decorator(detail=True, methods=['GET'])
    def revision(self, request, collection_uid=None, uid=None):
        col = get_object_or_404(self.get_collection_queryset(Collection.objects), main_item__uid=collection_uid)
        item = get_object_or_404(col.items, uid=uid)

        limit = int(request.GET.get('limit', 50))
        iterator = request.GET.get('iterator', None)

        queryset = item.revisions.order_by('-id')

        if iterator is not None:
            iterator = get_object_or_404(queryset, uid=iterator)
            queryset = queryset.filter(id__lt=iterator.id)

        queryset = queryset[:limit]
        serializer = CollectionItemRevisionSerializer(queryset, context=self.get_serializer_context(), many=True)

        # This is not the most efficient way of implementing this, but it's good enough
        done = len(queryset) < limit

        last_item = len(queryset) > 0 and serializer.data[-1]

        ret = {
            'data': serializer.data,
            'iterator': last_item and last_item['uid'],
            'done': done,
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

            queryset, stoken_rev = self.filter_by_stoken(request, queryset)

            uids, etags = zip(*[(item['uid'], item.get('etag')) for item in serializer.validated_data])
            revs = CollectionItemRevision.objects.filter(uid__in=etags, current=True)
            queryset = queryset.filter(uid__in=uids).exclude(revisions__in=revs)

            queryset, new_stoken = self.get_queryset_stoken(queryset)
            stoken = stoken_rev and stoken_rev.uid
            new_stoken = new_stoken or stoken

            serializer = self.get_serializer(queryset, many=True)

            ret = {
                'data': serializer.data,
                'stoken': new_stoken,
                'done': True,  # we always return all the items, so it's always done
            }
            return Response(ret)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action_decorator(detail=False, methods=['POST'])
    def batch(self, request, collection_uid=None):
        return self.transaction(request, collection_uid, validate_etag=False)

    @action_decorator(detail=False, methods=['POST'])
    def transaction(self, request, collection_uid=None, validate_etag=True):
        stoken = request.GET.get('stoken', None)
        with transaction.atomic():  # We need this for locking on the collection object
            collection_object = get_object_or_404(
                self.get_collection_queryset(Collection.objects).select_for_update(),  # Lock writes on the collection
                main_item__uid=collection_uid)

            if stoken is not None and stoken != collection_object.stoken:
                content = {'code': 'stale_stoken', 'detail': 'Stoken is too old'}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)

            items = request.data.get('items')
            deps = request.data.get('deps', None)
            # FIXME: It should just be one serializer
            context = self.get_serializer_context()
            context.update({'validate_etag': validate_etag})
            serializer = self.get_serializer_class()(data=items, context=context, many=True)
            deps_serializer = CollectionItemDepSerializer(data=deps, context=context, many=True)

            ser_valid = serializer.is_valid()
            deps_ser_valid = (deps is None or deps_serializer.is_valid())
            if ser_valid and deps_ser_valid:
                try:
                    items = serializer.save(collection=collection_object)
                except IntegrityError:
                    # FIXME: return the items with a bad token (including deps) so we don't have to fetch them after
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

    def get_serializer_class(self):
        return self.serializer_class

    def get_collection_queryset(self, queryset=Collection.objects):
        user = self.request.user
        return queryset.filter(members__user=user)

    def create(self, request, collection_uid=None, collection_item_uid=None):
        col = get_object_or_404(self.get_collection_queryset(), main_item__uid=collection_uid)
        col_it = get_object_or_404(col.items, uid=collection_item_uid)

        serializer = self.get_serializer_class()(data=request.data)
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

        col = get_object_or_404(self.get_collection_queryset(), main_item__uid=collection_uid)
        col_it = get_object_or_404(col.items, uid=collection_item_uid)
        chunk = get_object_or_404(col_it.chunks, uid=uid)

        filename = chunk.chunkFile.path
        dirname = os.path.dirname(filename)
        basename = os.path.basename(filename)

        # FIXME: DO NOT USE! Use django-send file or etc instead.
        return serve(request, basename, dirname)


class CollectionMemberViewSet(BaseViewSet):
    allowed_methods = ['GET', 'PUT', 'DELETE']
    our_base_permission_classes = BaseViewSet.permission_classes
    permission_classes = our_base_permission_classes + (permissions.IsCollectionAdmin, )
    queryset = CollectionMember.objects.all()
    serializer_class = CollectionMemberSerializer
    lookup_field = 'user__' + User.USERNAME_FIELD
    lookup_url_kwarg = 'username'
    stoken_id_fields = ['stoken__id']

    # FIXME: need to make sure that there's always an admin, and maybe also don't let an owner remove adm access
    # (if we want to transfer, we need to do that specifically)

    def get_queryset(self, queryset=None):
        collection_uid = self.kwargs['collection_uid']
        try:
            collection = self.get_collection_queryset(Collection.objects).get(main_item__uid=collection_uid)
        except Collection.DoesNotExist:
            raise Http404('Collection does not exist')

        if queryset is None:
            queryset = type(self).queryset

        return queryset.filter(collection=collection)

    # We override this method because we expect the stoken to be called iterator
    def get_stoken_obj_id(self, request):
        return request.GET.get('iterator', None)

    def list(self, request, collection_uid=None):
        queryset = self.get_queryset().order_by('id')
        queryset, new_stoken, done = self.filter_by_stoken_and_limit(request, queryset)
        serializer = self.get_serializer(queryset, many=True)

        ret = {
            'data': serializer.data,
            'iterator': new_stoken,  # Here we call it an iterator, it's only stoken for collection/items
            'done': done,
        }

        return Response(ret)

    def create(self, request):
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    # FIXME: block leaving if we are the last admins - should be deleted / assigned in this case depending if there
    # are other memebers.
    def perform_destroy(self, instance):
        instance.revoke()

    @action_decorator(detail=False, methods=['POST'], permission_classes=our_base_permission_classes)
    def leave(self, request, collection_uid=None):
        collection_uid = self.kwargs['collection_uid']
        col = get_object_or_404(self.get_collection_queryset(Collection.objects), main_item__uid=collection_uid)

        member = col.members.get(user=request.user)
        self.perform_destroy(member)

        return Response({})


class InvitationBaseViewSet(BaseViewSet):
    queryset = CollectionInvitation.objects.all()
    serializer_class = CollectionInvitationSerializer
    lookup_field = 'uid'
    lookup_url_kwarg = 'invitation_uid'

    def list(self, request, collection_uid=None):
        limit = int(request.GET.get('limit', 50))
        iterator = request.GET.get('iterator', None)

        queryset = self.get_queryset().order_by('id')

        if iterator is not None:
            iterator = get_object_or_404(queryset, uid=iterator)
            queryset = queryset.filter(id__gt=iterator.id)

        queryset = queryset[:limit]
        serializer = self.get_serializer(queryset, many=True)

        # This is not the most efficient way of implementing this, but it's good enough
        done = len(queryset) < limit

        last_item = len(queryset) > 0 and serializer.data[-1]

        ret = {
            'data': serializer.data,
            'iterator': last_item and last_item['uid'],
            'done': done,
        }

        return Response(ret)


class InvitationOutgoingViewSet(InvitationBaseViewSet):
    allowed_methods = ['GET', 'POST', 'PUT', 'DELETE']

    def get_queryset(self, queryset=None):
        if queryset is None:
            queryset = type(self).queryset

        return queryset.filter(fromMember__user=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            collection_uid = serializer.validated_data.get('collection', {}).get('uid')

            try:
                collection = self.get_collection_queryset(Collection.objects).get(main_item__uid=collection_uid)
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


class InvitationIncomingViewSet(InvitationBaseViewSet):
    allowed_methods = ['GET', 'DELETE']

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
    authentication_classes = BaseViewSet.authentication_classes

    def get_encryption_key(self, salt):
        key = nacl.hash.blake2b(settings.SECRET_KEY.encode(), encoder=nacl.encoding.RawEncoder)
        return nacl.hash.blake2b(b'', key=key, salt=salt[:nacl.hash.BLAKE2B_SALTBYTES], person=b'etebase-auth',
                                 encoder=nacl.encoding.RawEncoder)

    def get_queryset(self):
        return User.objects.all()

    def login_response_data(self, user):
        return {
            'token': AuthToken.objects.create(user=user).key,
            'user': UserSerializer(user).data,
        }

    def list(self, request):
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    @action_decorator(detail=False, methods=['POST'])
    def signup(self, request):
        serializer = AuthenticationSignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        data = self.login_response_data(user)
        return Response(data, status=status.HTTP_201_CREATED)

    def get_login_user(self, username):
        kwargs = {User.USERNAME_FIELD: username}
        return get_object_or_404(self.get_queryset(), **kwargs)

    def validate_login_request(self, request, validated_data, response_raw, signature, expected_action):
        from datetime import datetime

        username = validated_data.get('username')
        user = self.get_login_user(username)
        host = validated_data['host']
        challenge = validated_data['challenge']
        action = validated_data['action']

        salt = bytes(user.userinfo.salt)
        enc_key = self.get_encryption_key(salt)
        box = nacl.secret.SecretBox(enc_key)

        challenge_data = json.loads(box.decrypt(challenge).decode())
        now = int(datetime.now().timestamp())
        if action != expected_action:
            content = {'code': 'wrong_action', 'detail': 'Expected "{}" but got something else'.format(expected_action)}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)
        elif now - challenge_data['timestamp'] > app_settings.CHALLENGE_VALID_SECONDS:
            content = {'code': 'challenge_expired', 'detail': 'Login challange has expired'}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)
        elif challenge_data['userId'] != user.id:
            content = {'code': 'wrong_user', 'detail': 'This challenge is for the wrong user'}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)
        elif not settings.DEBUG and host != request.get_host():
            detail = 'Found wrong host name. Got: "{}" expected: "{}"'.format(host, request.get_host())
            content = {'code': 'wrong_host', 'detail': detail}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)

        verify_key = nacl.signing.VerifyKey(bytes(user.userinfo.loginPubkey), encoder=nacl.encoding.RawEncoder)

        try:
            verify_key.verify(response_raw, signature)
        except nacl.exceptions.BadSignatureError:
            return Response({'code': 'login_bad_signature'}, status=status.HTTP_400_BAD_REQUEST)

        return None

    @action_decorator(detail=False, methods=['POST'])
    def login_challenge(self, request):
        from datetime import datetime

        serializer = AuthenticationLoginChallengeSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username')
            user = self.get_login_user(username)

            salt = bytes(user.userinfo.salt)
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
        outer_serializer = AuthenticationLoginSerializer(data=request.data)
        outer_serializer.is_valid(raise_exception=True)

        response_raw = outer_serializer.validated_data['response']
        response = json.loads(response_raw.decode())
        signature = outer_serializer.validated_data['signature']

        serializer = AuthenticationLoginInnerSerializer(data=response, context={'host': request.get_host()})
        serializer.is_valid(raise_exception=True)

        bad_login_response = self.validate_login_request(
            request, serializer.validated_data, response_raw, signature, "login")
        if bad_login_response is not None:
            return bad_login_response

        username = serializer.validated_data.get('username')
        user = self.get_login_user(username)

        data = self.login_response_data(user)

        user_logged_in.send(sender=user.__class__, request=request, user=user)

        return Response(data, status=status.HTTP_200_OK)

    @action_decorator(detail=False, methods=['POST'], permission_classes=BaseViewSet.permission_classes)
    def logout(self, request):
        request.auth.delete()
        user_logged_out.send(sender=request.user.__class__, request=request, user=request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action_decorator(detail=False, methods=['POST'], permission_classes=BaseViewSet.permission_classes)
    def change_password(self, request):
        outer_serializer = AuthenticationLoginSerializer(data=request.data)
        outer_serializer.is_valid(raise_exception=True)

        response_raw = outer_serializer.validated_data['response']
        response = json.loads(response_raw.decode())
        signature = outer_serializer.validated_data['signature']

        serializer = AuthenticationChangePasswordInnerSerializer(
            request.user.userinfo, data=response, context={'host': request.get_host()})
        serializer.is_valid(raise_exception=True)

        bad_login_response = self.validate_login_request(
            request, serializer.validated_data, response_raw, signature, "changePassword")
        if bad_login_response is not None:
            return bad_login_response

        serializer.save()

        return Response({}, status=status.HTTP_200_OK)


class TestAuthenticationViewSet(viewsets.ViewSet):
    allowed_methods = ['POST']

    def list(self, request):
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    @action_decorator(detail=False, methods=['POST'])
    def reset(self, request, *args, **kwargs):
        # Only run when in DEBUG mode! It's only used for tests
        if not settings.DEBUG:
            return HttpResponseBadRequest("Only allowed in debug mode.")

        user = get_object_or_404(User.objects.all(), username=request.data.get('user').get('username'))

        # Only allow test users for extra safety
        if not getattr(user, User.USERNAME_FIELD).startswith('test_user'):
            return HttpResponseBadRequest("Endpoint not allowed for user.")

        if hasattr(user, 'userinfo'):
            user.userinfo.delete()

        serializer = AuthenticationSignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        # Delete all of the journal data for this user for a clear test env
        user.collection_set.all().delete()
        user.incoming_invitations.all().delete()

        # FIXME: also delete chunk files!!!

        return HttpResponse()
