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

import base64

from django.contrib.auth import get_user_model
from rest_framework import serializers
from . import models

User = get_user_model()


class BinaryBase64Field(serializers.Field):
    def to_representation(self, value):
        return base64.b64encode(value).decode('ascii')

    def to_internal_value(self, data):
        return base64.b64decode(data)


class CollectionSerializer(serializers.ModelSerializer):
    owner = serializers.SlugRelatedField(
        slug_field=User.USERNAME_FIELD,
        read_only=True
    )
    encryptionKey = serializers.SerializerMethodField('get_key_from_context')
    permissions = serializers.SerializerMethodField('get_permission_from_context')
    ctag = serializers.SerializerMethodField('get_ctag')

    class Meta:
        model = models.Collection
        fields = ('uid', 'version', 'owner', 'encryptionKey', 'permissions', 'ctag')

    def get_key_from_context(self, obj):
        request = self.context.get('request', None)
        if request is not None:
            return 'FIXME'
        return None

    def get_permission_from_context(self, obj):
        request = self.context.get('request', None)
        if request is not None:
            return 'FIXME'
        return 'readOnly'

    def get_ctag(self, obj):
        return 'FIXME'


class CollectionItemChunkSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.CollectionItemChunk
        fields = ('uid', )


class CollectionItemSnapshotSerializer(serializers.ModelSerializer):
    chunks = serializers.SlugRelatedField(
        slug_field='uid',
        queryset=models.CollectionItemChunk,
        many=True
    )

    class Meta:
        model = models.CollectionItemSnapshot
        fields = ('chunks', 'chunkHmac')


class CollectionItemSerializer(serializers.ModelSerializer):
    encryptionKey = BinaryBase64Field()
    content = CollectionItemSnapshotSerializer(
        read_only=True,
        many=False
    )

    class Meta:
        model = models.CollectionItem
        fields = ('uid', 'version', 'encryptionKey', 'content')
