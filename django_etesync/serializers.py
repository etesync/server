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
from django.db import transaction
from django.utils.crypto import get_random_string
from rest_framework import serializers
from . import models

User = get_user_model()


def generate_rev_uid(length=32):
    return get_random_string(length)


class BinaryBase64Field(serializers.Field):
    def to_representation(self, value):
        return base64.urlsafe_b64encode(value).decode('ascii')

    def to_internal_value(self, data):
        data += "=" * ((4 - len(data) % 4) % 4)
        return base64.urlsafe_b64decode(data)


class CollectionEncryptionKeyField(BinaryBase64Field):
    def get_attribute(self, instance):
        request = self.context.get('request', None)
        if request is not None:
            return instance.members.get(user=request.user).encryptionKey
        return None


class CollectionContentField(BinaryBase64Field):
    def get_attribute(self, instance):
        request = self.context.get('request', None)
        if request is not None:
            return instance.members.get(user=request.user).encryptionKey
        return None


class CollectionItemChunkSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.CollectionItemChunk
        fields = ('uid', 'chunkFile')


class CollectionItemRevisionBaseSerializer(serializers.ModelSerializer):
    chunks = serializers.SlugRelatedField(
        slug_field='uid',
        queryset=models.CollectionItemChunk.objects.all(),
        many=True
    )
    meta = BinaryBase64Field()

    class Meta:
        model = models.CollectionItemRevision
        fields = ('chunks', 'meta', 'uid', 'deleted')


class CollectionItemRevisionSerializer(CollectionItemRevisionBaseSerializer):
    chunksUrls = serializers.SerializerMethodField('get_chunks_urls')

    class Meta(CollectionItemRevisionBaseSerializer.Meta):
        fields = CollectionItemRevisionBaseSerializer.Meta.fields + ('chunksUrls', )

    # FIXME: currently the user is exposed in the url. We don't want that, and we can probably avoid that but still
    # save it under the user.
    # We would probably be better off just let the user calculate the urls from the uid and a base url for the snapshot.
    # E.g. chunkBaseUrl: "/media/bla/bla/" or chunkBaseUrl: "https://media.etesync.com/bla/bla"
    def get_chunks_urls(self, obj):
        ret = []
        for chunk in obj.chunks.all():
            ret.append(chunk.chunkFile.url)

        return ret


class CollectionItemRevisionInlineSerializer(CollectionItemRevisionBaseSerializer):
    chunksData = serializers.SerializerMethodField('get_chunks_data')

    class Meta(CollectionItemRevisionBaseSerializer.Meta):
        fields = CollectionItemRevisionBaseSerializer.Meta.fields + ('chunksData', )

    def get_chunks_data(self, obj):
        ret = []
        for chunk in obj.chunks.all():
            with open(chunk.chunkFile.path, 'rb') as f:
                ret.append(base64.b64encode(f.read()).decode('ascii'))

        return ret


class CollectionItemSerializer(serializers.ModelSerializer):
    encryptionKey = BinaryBase64Field()
    content = CollectionItemRevisionSerializer(many=False)

    class Meta:
        model = models.CollectionItem
        fields = ('uid', 'version', 'encryptionKey', 'content')

    def create(self, validated_data):
        """Function that's called when this serializer creates an item"""
        revision_data = validated_data.pop('content')
        instance = self.__class__.Meta.model(**validated_data)

        with transaction.atomic():
            instance.save()

            chunks = revision_data.pop('chunks')
            revision = models.CollectionItemRevision.objects.create(**revision_data, uid=generate_rev_uid(),
                                                                    item=instance)
            revision.chunks.set(chunks)

        return instance

    def update(self, instance, validated_data):
        """Function that's called when this serializer is meant to update an item"""
        revision_data = validated_data.pop('content')

        with transaction.atomic():
            # We don't have to use select_for_update here because the unique constraint on current guards against
            # the race condition. But it's a good idea because it'll lock and wait rather than fail.
            current_revision = instance.revisions.filter(current=True).select_for_update().first()
            current_revision.current = None
            current_revision.save()

            chunks = revision_data.pop('chunks')
            revision = models.CollectionItemRevision.objects.create(**revision_data, uid=generate_rev_uid(),
                                                                    item=instance)
            revision.chunks.set(chunks)

        return instance


class CollectionItemInlineSerializer(CollectionItemSerializer):
    content = CollectionItemRevisionInlineSerializer(read_only=True, many=False)


class CollectionSerializer(serializers.ModelSerializer):
    encryptionKey = CollectionEncryptionKeyField()
    accessLevel = serializers.SerializerMethodField('get_access_level_from_context')
    ctag = serializers.SerializerMethodField('get_ctag')
    content = CollectionItemRevisionSerializer(many=False)

    class Meta:
        model = models.Collection
        fields = ('uid', 'version', 'accessLevel', 'encryptionKey', 'content', 'ctag')

    def get_access_level_from_context(self, obj):
        request = self.context.get('request', None)
        if request is not None:
            return obj.members.get(user=request.user).accessLevel
        return None

    def get_ctag(self, obj):
        last_revision = models.CollectionItemRevision.objects.filter(item__collection=obj).last()
        if last_revision is None:
            # FIXME: what is the etag for None? Though if we use the revision for collection it should be shared anyway.
            return None

        return last_revision.uid

    def create(self, validated_data):
        """Function that's called when this serializer creates an item"""
        revision_data = validated_data.pop('content')
        encryption_key = validated_data.pop('encryptionKey')
        instance = self.__class__.Meta.model(**validated_data)

        with transaction.atomic():
            main_item = models.CollectionItem.objects.create(
                uid=None, encryptionKey=None, version=instance.version, collection=instance)
            instance.mainItem = main_item

            chunks = revision_data.pop('chunks')
            revision = models.CollectionItemRevision.objects.create(**revision_data, uid=generate_rev_uid(),
                                                                    item=main_item)
            revision.chunks.set(chunks)

            instance.save()
            models.CollectionMember(collection=instance,
                                    user=validated_data.get('owner'),
                                    accessLevel=models.CollectionMember.AccessLevels.ADMIN,
                                    encryptionKey=encryption_key,
                                    ).save()

        return instance
