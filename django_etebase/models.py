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

from pathlib import Path

from django.db import models, transaction
from django.conf import settings
from django.core.validators import RegexValidator
from django.db.models import Q
from django.utils.functional import cached_property
from django.utils.crypto import get_random_string


Base64Url256BitlValidator = RegexValidator(regex=r'^[a-zA-Z0-9\-_]{42,43}$', message='Expected a base64url.')
UidValidator = RegexValidator(regex=r'^[a-zA-Z0-9]*$', message='Not a valid UID')


class Collection(models.Model):
    main_item = models.ForeignKey('CollectionItem', related_name='parent', null=True, on_delete=models.SET_NULL)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return self.uid

    @cached_property
    def uid(self):
        return self.main_item.uid

    @property
    def content(self):
        return self.main_item.content

    @property
    def etag(self):
        return self.content.uid

    @cached_property
    def stoken(self):
        stoken = Stoken.objects.filter(
            Q(collectionitemrevision__item__collection=self) | Q(collectionmember__collection=self)
        ).order_by('id').last()

        if stoken is None:
            raise Exception('stoken is None. Should never happen')

        return stoken.uid


class CollectionItem(models.Model):
    uid = models.CharField(db_index=True, blank=False,
                           max_length=43, validators=[UidValidator])
    collection = models.ForeignKey(Collection, related_name='items', on_delete=models.CASCADE)
    version = models.PositiveSmallIntegerField()
    encryptionKey = models.BinaryField(editable=True, blank=False, null=True)

    class Meta:
        unique_together = ('uid', 'collection')

    def __str__(self):
        return '{} {}'.format(self.uid, self.collection.uid)

    @cached_property
    def content(self):
        return self.revisions.get(current=True)

    @property
    def etag(self):
        return self.content.uid


def chunk_directory_path(instance, filename):
    item = instance.item
    col = item.collection
    user_id = col.owner.id
    item_uid = item.uid or 'main'
    return Path('user_{}'.format(user_id), col.uid, item_uid, instance.uid)


class CollectionItemChunk(models.Model):
    uid = models.CharField(db_index=True, blank=False, null=False,
                           max_length=43, validators=[Base64Url256BitlValidator])
    item = models.ForeignKey(CollectionItem, related_name='chunks', on_delete=models.CASCADE)
    chunkFile = models.FileField(upload_to=chunk_directory_path, max_length=150, unique=True)

    def __str__(self):
        return self.uid


def generate_stoken_uid():
    return get_random_string(32, allowed_chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_')


class Stoken(models.Model):
    uid = models.CharField(db_index=True, unique=True, blank=False, null=False, default=generate_stoken_uid,
                           max_length=43, validators=[Base64Url256BitlValidator])


class CollectionItemRevision(models.Model):
    stoken = models.OneToOneField(Stoken, on_delete=models.PROTECT)
    uid = models.CharField(db_index=True, unique=True, blank=False, null=False,
                           max_length=43, validators=[Base64Url256BitlValidator])
    salt = models.BinaryField(editable=True, blank=False, null=False, default=b'')
    item = models.ForeignKey(CollectionItem, related_name='revisions', on_delete=models.CASCADE)
    meta = models.BinaryField(editable=True, blank=False, null=False)
    current = models.BooleanField(db_index=True, default=True, null=True)
    deleted = models.BooleanField(default=False)

    class Meta:
        unique_together = ('item', 'current')

    def __str__(self):
        return '{} {} current={}'.format(self.uid, self.item.uid, self.current)


class RevisionChunkRelation(models.Model):
    chunk = models.ForeignKey(CollectionItemChunk, related_name='revisions_relation', on_delete=models.CASCADE)
    revision = models.ForeignKey(CollectionItemRevision, related_name='chunks_relation', on_delete=models.CASCADE)

    class Meta:
        ordering = ('id', )


class AccessLevels(models.TextChoices):
    ADMIN = 'adm'
    READ_WRITE = 'rw'
    READ_ONLY = 'ro'


class CollectionMember(models.Model):
    stoken = models.OneToOneField(Stoken, on_delete=models.PROTECT, null=True)
    collection = models.ForeignKey(Collection, related_name='members', on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    encryptionKey = models.BinaryField(editable=True, blank=False, null=False)
    accessLevel = models.CharField(
        max_length=3,
        choices=AccessLevels.choices,
        default=AccessLevels.READ_ONLY,
    )

    class Meta:
        unique_together = ('user', 'collection')

    def __str__(self):
        return '{} {}'.format(self.collection.uid, self.user)

    def revoke(self):
        with transaction.atomic():
            CollectionMemberRemoved.objects.update_or_create(
                collection=self.collection, user=self.user,
                defaults={
                    'stoken': Stoken.objects.create(),
                },
            )

            self.delete()


class CollectionMemberRemoved(models.Model):
    stoken = models.OneToOneField(Stoken, on_delete=models.PROTECT, null=True)
    collection = models.ForeignKey(Collection, related_name='removed_members', on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('user', 'collection')

    def __str__(self):
        return '{} {}'.format(self.collection.uid, self.user)


class CollectionInvitation(models.Model):
    uid = models.CharField(db_index=True, blank=False, null=False,
                           max_length=43, validators=[Base64Url256BitlValidator])
    version = models.PositiveSmallIntegerField(default=1)
    fromMember = models.ForeignKey(CollectionMember, on_delete=models.CASCADE)
    # FIXME: make sure to delete all invitations for the same collection once one is accepted
    # Make sure to not allow invitations if already a member

    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='incoming_invitations', on_delete=models.CASCADE)
    signedEncryptionKey = models.BinaryField(editable=False, blank=False, null=False)
    accessLevel = models.CharField(
        max_length=3,
        choices=AccessLevels.choices,
        default=AccessLevels.READ_ONLY,
    )

    class Meta:
        unique_together = ('user', 'fromMember')

    def __str__(self):
        return '{} {}'.format(self.fromMember.collection.uid, self.user)

    @cached_property
    def collection(self):
        return self.fromMember.collection


class UserInfo(models.Model):
    owner = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, primary_key=True)
    version = models.PositiveSmallIntegerField(default=1)
    loginPubkey = models.BinaryField(editable=True, blank=False, null=False)
    pubkey = models.BinaryField(editable=True, blank=False, null=False)
    encryptedContent = models.BinaryField(editable=True, blank=False, null=False)
    salt = models.BinaryField(editable=True, blank=False, null=False)

    def __str__(self):
        return "UserInfo<{}>".format(self.owner)
