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

from django.core.files.base import ContentFile
from django.contrib.auth import get_user_model
from django.db import transaction
from rest_framework import serializers
from . import models

User = get_user_model()


def process_revisions_for_item(item, revision_data):
    chunks_objs = []
    chunks = revision_data.pop('chunks_relation')
    for chunk in chunks:
        uid = chunk[0]
        if len(chunk) > 1:
            content = chunk[1]
            chunk = models.CollectionItemChunk(uid=uid, item=item)
            chunk.chunkFile.save('IGNORED', ContentFile(content))
            chunk.save()
            chunks_objs.append(chunk)
        else:
            chunk = models.CollectionItemChunk.objects.get(uid=uid)
            chunks_objs.append(chunk)

    revision = models.CollectionItemRevision.objects.create(**revision_data, item=item)
    for chunk in chunks_objs:
        models.RevisionChunkRelation.objects.create(chunk=chunk, revision=revision)
    return revision


def b64encode(value):
    return base64.urlsafe_b64encode(value).decode('ascii').strip('=')


def b64decode(data):
    data += "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data)


class BinaryBase64Field(serializers.Field):
    def to_representation(self, value):
        return b64encode(value)

    def to_internal_value(self, data):
        return b64decode(data)


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


class ChunksField(serializers.RelatedField):
    def to_representation(self, obj):
        obj = obj.chunk
        inline = self.context.get('inline', False)
        if inline:
            with open(obj.chunkFile.path, 'rb') as f:
                return (obj.uid, b64encode(f.read()))
        else:
            return (obj.uid, )

    def to_internal_value(self, data):
        return (data[0], b64decode(data[1]))


class CollectionItemChunkSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.CollectionItemChunk
        fields = ('uid', 'chunkFile')


class CollectionItemRevisionSerializer(serializers.ModelSerializer):
    chunks = ChunksField(
        source='chunks_relation',
        queryset=models.RevisionChunkRelation.objects.all(),
        many=True
    )
    meta = BinaryBase64Field()

    class Meta:
        model = models.CollectionItemRevision
        fields = ('chunks', 'meta', 'uid', 'deleted')


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

            process_revisions_for_item(instance, revision_data)

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

            process_revisions_for_item(instance, revision_data)

        return instance


class CollectionSerializer(serializers.ModelSerializer):
    encryptionKey = CollectionEncryptionKeyField()
    accessLevel = serializers.SerializerMethodField('get_access_level_from_context')
    stoken = serializers.CharField(read_only=True)
    content = CollectionItemRevisionSerializer(many=False)

    class Meta:
        model = models.Collection
        fields = ('uid', 'version', 'accessLevel', 'encryptionKey', 'content', 'stoken')

    def get_access_level_from_context(self, obj):
        request = self.context.get('request', None)
        if request is not None:
            return obj.members.get(user=request.user).accessLevel
        return None

    def create(self, validated_data):
        """Function that's called when this serializer creates an item"""
        revision_data = validated_data.pop('content')
        encryption_key = validated_data.pop('encryptionKey')
        instance = self.__class__.Meta.model(**validated_data)

        with transaction.atomic():
            instance.save()
            main_item = models.CollectionItem.objects.create(
                uid=None, encryptionKey=None, version=instance.version, collection=instance)

            process_revisions_for_item(main_item, revision_data)

            models.CollectionMember(collection=instance,
                                    user=validated_data.get('owner'),
                                    accessLevel=models.CollectionMember.AccessLevels.ADMIN,
                                    encryptionKey=encryption_key,
                                    ).save()

        return instance

    def update(self, instance, validated_data):
        """Function that's called when this serializer is meant to update an item"""
        revision_data = validated_data.pop('content')

        with transaction.atomic():
            main_item = instance.main_item
            # We don't have to use select_for_update here because the unique constraint on current guards against
            # the race condition. But it's a good idea because it'll lock and wait rather than fail.
            current_revision = main_item.revisions.filter(current=True).select_for_update().first()
            current_revision.current = None
            current_revision.save()

            process_revisions_for_item(main_item, revision_data)

        return instance


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (User.USERNAME_FIELD, User.EMAIL_FIELD)


class AuthenticationSignupSerializer(serializers.Serializer):
    user = UserSerializer(many=False)
    salt = BinaryBase64Field()
    pubkey = BinaryBase64Field()

    def create(self, validated_data):
        """Function that's called when this serializer creates an item"""
        salt = validated_data.pop('salt')
        pubkey = validated_data.pop('pubkey')

        with transaction.atomic():
            instance = UserSerializer.Meta.model.objects.create(**validated_data)
            instance.set_unusable_password()

            models.UserInfo.objects.create(salt=salt, pubkey=pubkey, owner=instance)

        return instance

    def update(self, instance, validated_data):
        raise NotImplementedError()


class AuthenticationLoginChallengeSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)

    def validate(self, data):
        if not data.get('email') and not data.get('username'):
            raise serializers.ValidationError('Either email or username must be set')
        return data

    def create(self, validated_data):
        raise NotImplementedError()

    def update(self, instance, validated_data):
        raise NotImplementedError()


class AuthenticationLoginSerializer(serializers.Serializer):
    response = BinaryBase64Field()
    signature = BinaryBase64Field()

    def create(self, validated_data):
        raise NotImplementedError()

    def update(self, instance, validated_data):
        raise NotImplementedError()


class AuthenticationLoginInnerSerializer(AuthenticationLoginChallengeSerializer):
    challenge = BinaryBase64Field()
    host = serializers.CharField()

    def create(self, validated_data):
        raise NotImplementedError()

    def update(self, instance, validated_data):
        raise NotImplementedError()
