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
from django.core import exceptions as django_exceptions
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from rest_framework import serializers, status
from . import models
from .utils import get_user_queryset, create_user

from .exceptions import EtebaseValidationError

User = get_user_model()


def process_revisions_for_item(item, revision_data):
    chunks_objs = []
    chunks = revision_data.pop('chunks_relation')
    for chunk in chunks:
        uid = chunk[0]
        chunk_obj = models.CollectionItemChunk.objects.filter(uid=uid).first()
        if len(chunk) > 1:
            content = chunk[1]
            # If the chunk already exists we assume it's fine. Otherwise, we upload it.
            if chunk_obj is None:
                chunk_obj = models.CollectionItemChunk(uid=uid, collection=item.collection)
                chunk_obj.chunkFile.save('IGNORED', ContentFile(content))
                chunk_obj.save()
        else:
            if chunk_obj is None:
                raise EtebaseValidationError('chunk_no_content', 'Tried to create a new chunk without content')

        chunks_objs.append(chunk_obj)

    stoken = models.Stoken.objects.create()

    revision = models.CollectionItemRevision.objects.create(**revision_data, item=item, stoken=stoken)
    for chunk in chunks_objs:
        models.RevisionChunkRelation.objects.create(chunk=chunk, revision=revision)
    return revision


def b64encode(value):
    return base64.urlsafe_b64encode(value).decode('ascii').strip('=')


def b64decode(data):
    data += "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data)


def b64decode_or_bytes(data):
    if isinstance(data, bytes):
        return data
    else:
        return b64decode(data)


class BinaryBase64Field(serializers.Field):
    def to_representation(self, value):
        return value

    def to_internal_value(self, data):
        return b64decode_or_bytes(data)


class CollectionEncryptionKeyField(BinaryBase64Field):
    def get_attribute(self, instance):
        request = self.context.get('request', None)
        if request is not None:
            return instance.members.get(user=request.user).encryptionKey
        return None


class CollectionTypeField(BinaryBase64Field):
    def get_attribute(self, instance):
        request = self.context.get('request', None)
        if request is not None:
            collection_type = instance.members.get(user=request.user).collectionType
            return collection_type and collection_type.uid
        return None


class UserSlugRelatedField(serializers.SlugRelatedField):
    def get_queryset(self):
        view = self.context.get('view', None)
        return get_user_queryset(super().get_queryset(), view)

    def __init__(self, **kwargs):
        super().__init__(slug_field=User.USERNAME_FIELD, **kwargs)

    def to_internal_value(self, data):
        return super().to_internal_value(data.lower())


class ChunksField(serializers.RelatedField):
    def to_representation(self, obj):
        obj = obj.chunk
        if self.context.get('prefetch') == 'auto':
            with open(obj.chunkFile.path, 'rb') as f:
                return (obj.uid, f.read())
        else:
            return (obj.uid, )

    def to_internal_value(self, data):
        if data[0] is None or data[1] is None:
            raise EtebaseValidationError('no_null', 'null is not allowed')
        return (data[0], b64decode_or_bytes(data[1]))


class BetterErrorsMixin:
    @property
    def errors(self):
        nice = []
        errors = super().errors
        for error_type in errors:
            if error_type == 'non_field_errors':
                nice.extend(
                    self.flatten_errors(None, errors[error_type])
                )
            else:
                nice.extend(
                    self.flatten_errors(error_type, errors[error_type])
                )
        if nice:
            return {'code': 'field_errors',
                    'detail': 'Field validations failed.',
                    'errors': nice}
        return {}

    def flatten_errors(self, field_name, errors):
        ret = []
        if isinstance(errors, dict):
            for error_key in errors:
                error = errors[error_key]
                ret.extend(self.flatten_errors("{}.{}".format(field_name, error_key), error))
        else:
            for error in errors:
                if hasattr(error, 'detail'):
                    message = error.detail[0]
                elif hasattr(error, 'message'):
                    message = error.message
                else:
                    message = str(error)
                ret.append({
                    'field': field_name,
                    'code': error.code,
                    'detail': message,
                })
        return ret

    def transform_validation_error(self, prefix, err):
        if hasattr(err, 'error_dict'):
            errors = self.flatten_errors(prefix, err.error_dict)
        elif not hasattr(err, 'message'):
            errors = self.flatten_errors(prefix, err.error_list)
        else:
            raise EtebaseValidationError(err.code, err.message)

        raise serializers.ValidationError({
            'code': 'field_errors',
            'detail': 'Field validations failed.',
            'errors': errors,
        })


class CollectionItemChunkSerializer(BetterErrorsMixin, serializers.ModelSerializer):
    class Meta:
        model = models.CollectionItemChunk
        fields = ('uid', 'chunkFile')


class CollectionItemRevisionSerializer(BetterErrorsMixin, serializers.ModelSerializer):
    chunks = ChunksField(
        source='chunks_relation',
        queryset=models.RevisionChunkRelation.objects.all(),
        style={'base_template': 'input.html'},
        many=True
    )
    meta = BinaryBase64Field()

    class Meta:
        model = models.CollectionItemRevision
        fields = ('chunks', 'meta', 'uid', 'deleted')


class CollectionItemSerializer(BetterErrorsMixin, serializers.ModelSerializer):
    encryptionKey = BinaryBase64Field(required=False, default=None, allow_null=True)
    etag = serializers.CharField(allow_null=True, write_only=True)
    content = CollectionItemRevisionSerializer(many=False)

    class Meta:
        model = models.CollectionItem
        fields = ('uid', 'version', 'encryptionKey', 'content', 'etag')

    def create(self, validated_data):
        """Function that's called when this serializer creates an item"""
        validate_etag = self.context.get('validate_etag', False)
        etag = validated_data.pop('etag')
        revision_data = validated_data.pop('content')
        uid = validated_data.pop('uid')

        Model = self.__class__.Meta.model

        with transaction.atomic():
            instance, created = Model.objects.get_or_create(uid=uid, defaults=validated_data)
            cur_etag = instance.etag if not created else None

            if validate_etag and cur_etag != etag:
                raise EtebaseValidationError('wrong_etag', 'Wrong etag. Expected {} got {}'.format(cur_etag, etag),
                                             status_code=status.HTTP_409_CONFLICT)

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


class CollectionItemDepSerializer(BetterErrorsMixin, serializers.ModelSerializer):
    etag = serializers.CharField()

    class Meta:
        model = models.CollectionItem
        fields = ('uid', 'etag')

    def validate(self, data):
        item = self.__class__.Meta.model.objects.get(uid=data['uid'])
        etag = data['etag']
        if item.etag != etag:
            raise EtebaseValidationError('wrong_etag', 'Wrong etag. Expected {} got {}'.format(item.etag, etag),
                                         status_code=status.HTTP_409_CONFLICT)

        return data


class CollectionItemBulkGetSerializer(BetterErrorsMixin, serializers.ModelSerializer):
    etag = serializers.CharField(required=False)

    class Meta:
        model = models.CollectionItem
        fields = ('uid', 'etag')


class CollectionListMultiSerializer(BetterErrorsMixin, serializers.Serializer):
    collectionTypes = serializers.ListField(
        child=BinaryBase64Field()
    )


class CollectionSerializer(BetterErrorsMixin, serializers.ModelSerializer):
    collectionKey = CollectionEncryptionKeyField()
    # FIXME: make required once "collection-type-migration" is done
    collectionType = CollectionTypeField(required=False)
    accessLevel = serializers.SerializerMethodField('get_access_level_from_context')
    stoken = serializers.CharField(read_only=True)

    item = CollectionItemSerializer(many=False, source='main_item')

    class Meta:
        model = models.Collection
        fields = ('item', 'accessLevel', 'collectionKey', 'collectionType', 'stoken')

    def get_access_level_from_context(self, obj):
        request = self.context.get('request', None)
        if request is not None:
            return obj.members.get(user=request.user).accessLevel
        return None

    def create(self, validated_data):
        """Function that's called when this serializer creates an item"""
        collection_key = validated_data.pop('collectionKey')
        # FIXME: remove the None fallback once "collection-type-migration" is done
        collection_type = validated_data.pop('collectionType', None)

        main_item_data = validated_data.pop('main_item')
        etag = main_item_data.pop('etag')
        revision_data = main_item_data.pop('content')

        instance = self.__class__.Meta.model(**validated_data)

        with transaction.atomic():
            if etag is not None:
                raise EtebaseValidationError('bad_etag', 'etag is not null')

            instance.save()
            main_item = models.CollectionItem.objects.create(**main_item_data, collection=instance)

            instance.main_item = main_item

            instance.full_clean()
            instance.save()

            process_revisions_for_item(main_item, revision_data)

            user = validated_data.get('owner')

            # FIXME: remove the if statement (and else branch) once "collection-type-migration" is done
            if collection_type is not None:
                collection_type_obj, _ = models.CollectionType.objects.get_or_create(uid=collection_type, owner=user)
            else:
                collection_type_obj = None

            models.CollectionMember(collection=instance,
                                    stoken=models.Stoken.objects.create(),
                                    user=user,
                                    accessLevel=models.AccessLevels.ADMIN,
                                    encryptionKey=collection_key,
                                    collectionType=collection_type_obj,
                                    ).save()

        return instance

    def update(self, instance, validated_data):
        raise NotImplementedError()


class CollectionMemberSerializer(BetterErrorsMixin, serializers.ModelSerializer):
    username = UserSlugRelatedField(
        source='user',
        read_only=True,
        style={'base_template': 'input.html'},
    )

    class Meta:
        model = models.CollectionMember
        fields = ('username', 'accessLevel')

    def create(self, validated_data):
        raise NotImplementedError()

    def update(self, instance, validated_data):
        with transaction.atomic():
            # We only allow updating accessLevel
            access_level = validated_data.pop('accessLevel')
            if instance.accessLevel != access_level:
                instance.stoken = models.Stoken.objects.create()
                instance.accessLevel = access_level
                instance.save()

        return instance


class CollectionInvitationSerializer(BetterErrorsMixin, serializers.ModelSerializer):
    username = UserSlugRelatedField(
        source='user',
        queryset=User.objects,
        style={'base_template': 'input.html'},
    )
    collection = serializers.CharField(source='collection.uid')
    fromUsername = BinaryBase64Field(source='fromMember.user.username', read_only=True)
    fromPubkey = BinaryBase64Field(source='fromMember.user.userinfo.pubkey', read_only=True)
    signedEncryptionKey = BinaryBase64Field()

    class Meta:
        model = models.CollectionInvitation
        fields = ('username', 'uid', 'collection', 'signedEncryptionKey', 'accessLevel',
                  'fromUsername', 'fromPubkey', 'version')

    def validate_user(self, value):
        request = self.context['request']

        if request.user.username == value.lower():
            raise EtebaseValidationError('no_self_invite', 'Inviting yourself is not allowed')
        return value

    def create(self, validated_data):
        request = self.context['request']
        collection = validated_data.pop('collection')

        member = collection.members.get(user=request.user)

        with transaction.atomic():
            try:
                return type(self).Meta.model.objects.create(**validated_data, fromMember=member)
            except IntegrityError:
                raise EtebaseValidationError('invitation_exists', 'Invitation already exists')

    def update(self, instance, validated_data):
        with transaction.atomic():
            instance.accessLevel = validated_data.pop('accessLevel')
            instance.signedEncryptionKey = validated_data.pop('signedEncryptionKey')
            instance.save()

        return instance


class InvitationAcceptSerializer(BetterErrorsMixin, serializers.Serializer):
    collectionType = BinaryBase64Field()
    encryptionKey = BinaryBase64Field()

    def create(self, validated_data):

        with transaction.atomic():
            invitation = self.context['invitation']
            encryption_key = validated_data.get('encryptionKey')
            collection_type = validated_data.pop('collectionType')

            user = invitation.user
            collection_type_obj, _ = models.CollectionType.objects.get_or_create(uid=collection_type, owner=user)

            member = models.CollectionMember.objects.create(
                collection=invitation.collection,
                stoken=models.Stoken.objects.create(),
                user=user,
                accessLevel=invitation.accessLevel,
                encryptionKey=encryption_key,
                collectionType=collection_type_obj,
                )

            models.CollectionMemberRemoved.objects.filter(
                user=invitation.user, collection=invitation.collection).delete()

            invitation.delete()

            return member

    def update(self, instance, validated_data):
        raise NotImplementedError()


class UserSerializer(BetterErrorsMixin, serializers.ModelSerializer):
    pubkey = BinaryBase64Field(source='userinfo.pubkey')
    encryptedContent = BinaryBase64Field(source='userinfo.encryptedContent')

    class Meta:
        model = User
        fields = (User.USERNAME_FIELD, User.EMAIL_FIELD, 'pubkey', 'encryptedContent')


class UserInfoPubkeySerializer(BetterErrorsMixin, serializers.ModelSerializer):
    pubkey = BinaryBase64Field()

    class Meta:
        model = models.UserInfo
        fields = ('pubkey', )


class UserSignupSerializer(BetterErrorsMixin, serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (User.USERNAME_FIELD, User.EMAIL_FIELD)
        extra_kwargs = {
            'username': {'validators': []},  # We specifically validate in SignupSerializer
        }


class AuthenticationSignupSerializer(BetterErrorsMixin, serializers.Serializer):
    """Used both for creating new accounts and setting up existing ones for the first time.
    When setting up existing ones the email is ignored."
    """
    user = UserSignupSerializer(many=False)
    salt = BinaryBase64Field()
    loginPubkey = BinaryBase64Field()
    pubkey = BinaryBase64Field()
    encryptedContent = BinaryBase64Field()

    def create(self, validated_data):
        """Function that's called when this serializer creates an item"""
        user_data = validated_data.pop('user')

        with transaction.atomic():
            try:
                view = self.context.get('view', None)
                user_queryset = get_user_queryset(User.objects.all(), view)
                instance = user_queryset.get(**{User.USERNAME_FIELD: user_data['username'].lower()})
            except User.DoesNotExist:
                # Create the user and save the casing the user chose as the first name
                try:
                    instance = create_user(**user_data, password=None, first_name=user_data['username'], view=view)
                    instance.clean_fields()
                except EtebaseValidationError as e:
                    raise e
                except django_exceptions.ValidationError as e:
                    self.transform_validation_error("user", e)
                except Exception as e:
                    raise EtebaseValidationError('generic', str(e))

            if hasattr(instance, 'userinfo'):
                raise EtebaseValidationError('user_exists', 'User already exists', status_code=status.HTTP_409_CONFLICT)

            models.UserInfo.objects.create(**validated_data, owner=instance)

        return instance

    def update(self, instance, validated_data):
        raise NotImplementedError()


class AuthenticationLoginChallengeSerializer(BetterErrorsMixin, serializers.Serializer):
    username = serializers.CharField(required=True)

    def create(self, validated_data):
        raise NotImplementedError()

    def update(self, instance, validated_data):
        raise NotImplementedError()


class AuthenticationLoginSerializer(BetterErrorsMixin, serializers.Serializer):
    response = BinaryBase64Field()
    signature = BinaryBase64Field()

    def create(self, validated_data):
        raise NotImplementedError()

    def update(self, instance, validated_data):
        raise NotImplementedError()


class AuthenticationLoginInnerSerializer(AuthenticationLoginChallengeSerializer):
    challenge = BinaryBase64Field()
    host = serializers.CharField()
    action = serializers.CharField()

    def create(self, validated_data):
        raise NotImplementedError()

    def update(self, instance, validated_data):
        raise NotImplementedError()


class AuthenticationChangePasswordInnerSerializer(AuthenticationLoginInnerSerializer):
    loginPubkey = BinaryBase64Field()
    encryptedContent = BinaryBase64Field()

    class Meta:
        model = models.UserInfo
        fields = ('loginPubkey', 'encryptedContent')

    def create(self, validated_data):
        raise NotImplementedError()

    def update(self, instance, validated_data):
        with transaction.atomic():
            instance.loginPubkey = validated_data.pop('loginPubkey')
            instance.encryptedContent = validated_data.pop('encryptedContent')
            instance.save()

        return instance
