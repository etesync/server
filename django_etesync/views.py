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

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.db.models import Max
from django.http import HttpResponseBadRequest, HttpResponse, Http404
from django.shortcuts import get_object_or_404

from rest_framework import status
from rest_framework import viewsets
from rest_framework import parsers
from rest_framework.decorators import action as action_decorator
from rest_framework.response import Response

from . import app_settings
from .models import Collection, CollectionItem, CollectionItemRevision
from .serializers import (
        CollectionSerializer,
        CollectionItemSerializer,
        CollectionItemRevisionSerializer,
        CollectionItemChunkSerializer
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
        return Response(serializer.data)

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
