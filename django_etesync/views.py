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
from django.contrib.auth import login, get_user_model
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponseBadRequest, HttpResponse, Http404
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from rest_framework import status
from rest_framework import viewsets
from rest_framework import parsers
from rest_framework.decorators import action as action_decorator
from rest_framework.response import Response

from . import app_settings, paginators
from .models import Collection, CollectionItem, CollectionItemChunk
from .serializers import (
        CollectionSerializer,
        CollectionItemSerializer,
        CollectionItemInlineSerializer,
        CollectionItemSnapshotSerializer,
        CollectionItemSnapshotInlineSerializer,
        CollectionItemChunkSerializer
    )


User = get_user_model()


class BaseViewSet(viewsets.ModelViewSet):
    authentication_classes = tuple(app_settings.API_AUTHENTICATORS)
    permission_classes = tuple(app_settings.API_PERMISSIONS)

    def get_serializer_class(self):
        serializer_class = self.serializer_class

        if self.request.method == 'PUT':
            serializer_class = getattr(self, 'serializer_update_class', serializer_class)

        return serializer_class

    def get_collection_queryset(self, queryset=Collection.objects):
        return queryset.all()


class CollectionViewSet(BaseViewSet):
    allowed_methods = ['GET', 'POST', 'DELETE']
    permission_classes = BaseViewSet.permission_classes
    queryset = Collection.objects.all()
    serializer_class = CollectionSerializer
    lookup_field = 'uid'

    def get_queryset(self):
        queryset = type(self).queryset
        return self.get_collection_queryset(queryset)

    def destroy(self, request, uid=None):
        # FIXME: implement
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            try:
                with transaction.atomic():
                    serializer.save(owner=self.request.user)
            except IntegrityError:
                content = {'code': 'integrity_error'}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)

            return Response({}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def list(self, request):
        queryset = self.get_queryset()

        serializer = self.serializer_class(queryset, context={'request': request}, many=True)
        return Response(serializer.data)


class CollectionItemViewSet(BaseViewSet):
    allowed_methods = ['GET', 'POST']
    permission_classes = BaseViewSet.permission_classes
    queryset = CollectionItem.objects.all()
    serializer_class = CollectionItemSerializer
    pagination_class = paginators.LinkHeaderPagination
    lookup_field = 'uid'

    def get_serializer_class(self):
        if self.request.method == 'GET' and self.request.query_params.get('prefer_inline'):
            return CollectionItemInlineSerializer

        return super().get_serializer_class()

    def get_queryset(self):
        collection_uid = self.kwargs['collection_uid']
        try:
            collection = self.get_collection_queryset(Collection.objects).get(uid=collection_uid)
        except Collection.DoesNotExist:
            raise Http404("Collection does not exist")
        # XXX Potentially add this for performance: .prefetch_related('snapshots__chunks')
        queryset = type(self).queryset.filter(collection__pk=collection.pk)

        return queryset

    def create(self, request, collection_uid=None):
        collection_object = self.get_collection_queryset(Collection.objects).get(uid=collection_uid)

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
        # FIXME: implement
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def update(self, request, collection_uid=None, uid=None):
        # FIXME: implement, or should it be implemented elsewhere?
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def partial_update(self, request, collection_uid=None, uid=None):
        # FIXME: implement, or should it be implemented elsewhere?
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    @action_decorator(detail=True, methods=['GET'])
    def snapshots(self, request, collection_uid=None, uid=None):
        col = get_object_or_404(Collection.objects, uid=collection_uid)
        col_it = get_object_or_404(col.items, uid=uid)

        serializer = CollectionItemSnapshotSerializer(col_it.snapshots, many=True)
        return Response(serializer.data)


class CollectionItemChunkViewSet(viewsets.ViewSet):
    allowed_methods = ['GET', 'POST']
    parser_classes = (parsers.MultiPartParser, )
    authentication_classes = BaseViewSet.authentication_classes
    permission_classes = BaseViewSet.permission_classes
    serializer_class = CollectionItemChunkSerializer
    lookup_field = 'uid'

    def get_collection_queryset(self, queryset=Collection.objects):
        return queryset.all()

    def create(self, request, collection_uid=None, collection_item_uid=None):
        col = get_object_or_404(self.get_collection_queryset(), uid=collection_uid)
        col_it = get_object_or_404(col.items, uid=collection_item_uid)

        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            try:
                serializer.save(item=col_it, order='abc')
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
