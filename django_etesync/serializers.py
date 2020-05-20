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
    stoken = serializers.CharField(allow_null=True)
    content = CollectionItemRevisionSerializer(many=False)

    class Meta:
        model = models.CollectionItem
        fields = ('uid', 'version', 'encryptionKey', 'content', 'stoken')

    def create(self, validated_data):
        """Function that's called when this serializer creates an item"""
        validate_stoken = self.context.get('validate_stoken', False)
        stoken = validated_data.pop('stoken')
        revision_data = validated_data.pop('content')
        uid = validated_data.pop('uid')

        Model = self.__class__.Meta.model

        with transaction.atomic():
            instance, created = Model.objects.get_or_create(uid=uid, defaults=validated_data)
            cur_stoken = instance.stoken if not created else None

            if validate_stoken and cur_stoken != stoken:
                raise serializers.ValidationError('Wrong stoken. Expected {} got {}'.format(cur_stoken, stoken))

            if not created:
                # We don't have to use select_for_update here because the unique constraint on current guards against
                # the race condition. But it's a good idea because it'll lock and wait rather than fail.
                current_revision = instance.revisions.filter(current=True).select_for_update().first()
                current_revision.current = None
                current_revision.save()

            process_revisions_for_item(instance, revision_data)

        return instance

    def update(self, instance, validated_data):
        # We never update, we always update in the create method
        raise NotImplementedError()


class CollectionItemDepSerializer(serializers.ModelSerializer):
    stoken = serializers.CharField()

    class Meta:
        model = models.CollectionItem
        fields = ('uid', 'stoken')

    def validate(self, data):
        item = self.__class__.Meta.model.objects.get(uid=data['uid'])
        stoken = data['stoken']
        if item.stoken != stoken:
            raise serializers.ValidationError('Wrong stoken. Expected {} got {}'.format(item.stoken, stoken))

        return data


class CollectionItemBulkGetSerializer(serializers.ModelSerializer):
    stoken = serializers.CharField(required=False)

    class Meta:
        model = models.CollectionItem
        fields = ('uid', 'stoken')


class CollectionSerializer(serializers.ModelSerializer):
    encryptionKey = CollectionEncryptionKeyField()
    accessLevel = serializers.SerializerMethodField('get_access_level_from_context')
    cstoken = serializers.CharField(read_only=True)
    stoken = serializers.CharField(allow_null=True)
    content = CollectionItemRevisionSerializer(many=False)

    class Meta:
        model = models.Collection
        fields = ('uid', 'version', 'accessLevel', 'encryptionKey', 'content', 'cstoken', 'stoken')

    def get_access_level_from_context(self, obj):
        request = self.context.get('request', None)
        if request is not None:
            return obj.members.get(user=request.user).accessLevel
        return None

    def create(self, validated_data):
        """Function that's called when this serializer creates an item"""
        stoken = validated_data.pop('stoken')
        revision_data = validated_data.pop('content')
        encryption_key = validated_data.pop('encryptionKey')
        instance = self.__class__.Meta.model(**validated_data)

        with transaction.atomic():
            if stoken is not None:
                raise serializers.ValidationError('Stoken is not None')

            instance.save()
            main_item = models.CollectionItem.objects.create(
                uid=None, encryptionKey=None, version=instance.version, collection=instance)

            process_revisions_for_item(main_item, revision_data)

            models.CollectionMember(collection=instance,
                                    user=validated_data.get('owner'),
                                    accessLevel=models.AccessLevels.ADMIN,
                                    encryptionKey=encryption_key,
                                    ).save()

        return instance

    def update(self, instance, validated_data):
        """Function that's called when this serializer is meant to update an item"""
        stoken = validated_data.pop('stoken')
        revision_data = validated_data.pop('content')

        with transaction.atomic():
            if stoken != instance.stoken:
                raise serializers.ValidationError('Wrong stoken. Expected {} got {}'.format(instance.stoken, stoken))

            main_item = instance.main_item
            # We don't have to use select_for_update here because the unique constraint on current guards against
            # the race condition. But it's a good idea because it'll lock and wait rather than fail.
            current_revision = main_item.revisions.filter(current=True).select_for_update().first()
            current_revision.current = None
            current_revision.save()

            process_revisions_for_item(main_item, revision_data)

        return instance


class CollectionMemberSerializer(serializers.ModelSerializer):
    username = serializers.SlugRelatedField(
        source='user',
        slug_field=User.USERNAME_FIELD,
        queryset=User.objects
    )
    encryptionKey = BinaryBase64Field()

    class Meta:
        model = models.CollectionMember
        fields = ('username', 'encryptionKey', 'accessLevel')

    def create(self, validated_data):
        raise NotImplementedError()

    def update(self, instance, validated_data):
        with transaction.atomic():
            # We only allow updating accessLevel
            instance.accessLevel = validated_data.pop('accessLevel')
            instance.save()

        return instance


class CollectionInvitationSerializer(serializers.ModelSerializer):
    username = serializers.SlugRelatedField(
        source='user',
        slug_field=User.USERNAME_FIELD,
        queryset=User.objects
    )
    collection = serializers.SerializerMethodField('get_collection')
    fromPubkey = serializers.SerializerMethodField('get_from_pubkey')
    signedEncryptionKey = BinaryBase64Field()

    class Meta:
        model = models.CollectionInvitation
        fields = ('username', 'uid', 'collection', 'signedEncryptionKey', 'accessLevel', 'fromPubkey', 'version')

    def get_collection(self, obj):
        return obj.collection.uid

    def get_from_pubkey(self, obj):
        return b64encode(obj.fromMember.user.userinfo.pubkey)

    def create(self, validated_data):
        collection = self.context['collection']
        request = self.context['request']

        if request.user == validated_data.get('user'):
            raise serializers.ValidationError('Inviting yourself is not allowed')

        member = collection.members.get(user=request.user)

        with transaction.atomic():
            return type(self).Meta.model.objects.create(**validated_data, fromMember=member)

    def update(self, instance, validated_data):
        with transaction.atomic():
            instance.accessLevel = validated_data.pop('accessLevel')
            instance.signedEncryptionKey = validated_data.pop('signedEncryptionKey')
            instance.save()

        return instance


class InvitationAcceptSerializer(serializers.Serializer):
    encryptionKey = BinaryBase64Field()

    def create(self, validated_data):

        with transaction.atomic():
            invitation = self.context['invitation']
            encryption_key = validated_data.get('encryptionKey')

            member = models.CollectionMember.objects.create(
                    collection=invitation.collection,
                    user=invitation.user,
                    accessLevel=invitation.accessLevel,
                    encryptionKey=encryption_key,
                    )

            invitation.delete()

            return member

    def update(self, instance, validated_data):
        raise NotImplementedError()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (User.USERNAME_FIELD, User.EMAIL_FIELD)


class UserQuerySerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (User.USERNAME_FIELD, User.EMAIL_FIELD)


class AuthenticationSignupSerializer(serializers.Serializer):
    user = UserQuerySerializer(many=False)
    salt = BinaryBase64Field()
    pubkey = BinaryBase64Field()

    def create(self, validated_data):
        """Function that's called when this serializer creates an item"""
        user_data = validated_data.pop('user')
        salt = validated_data.pop('salt')
        pubkey = validated_data.pop('pubkey')

        with transaction.atomic():
            instance = User.objects.get_or_create(**user_data)
            if hasattr(instance, 'userinfo'):
                raise serializers.ValidationError('User already exists')

            instance.set_unusable_password()
            # FIXME: send email verification

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
