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

from django.db import models
from django.conf import settings
from django.core.validators import RegexValidator
from django.utils.functional import cached_property


Base64Url256BitValidator = RegexValidator(regex=r'^[a-zA-Z0-9\-_]{43}$', message='Expected a 256bit base64url.')
UidValidator = RegexValidator(regex=r'[a-zA-Z0-9]', message='Not a valid UID')


class Collection(models.Model):
    uid = models.CharField(db_index=True, blank=False, null=False,
                           max_length=44, validators=[UidValidator])
    version = models.PositiveSmallIntegerField()
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('uid', 'owner')

    def __str__(self):
        return self.uid

    @cached_property
    def main_item(self):
        return self.items.get(uid=None)

    @cached_property
    def content(self):
        return self.main_item.content

    @cached_property
    def stoken(self):
        return self.main_item.stoken

    @cached_property
    def cstoken(self):
        last_revision = CollectionItemRevision.objects.filter(item__collection=self).last()
        if last_revision is None:
            # FIXME: what is the etag for None? Though if we use the revision for collection it should be shared anyway.
            return None

        return last_revision.uid


class CollectionItem(models.Model):
    uid = models.CharField(db_index=True, blank=False, null=True,
                           max_length=44, validators=[UidValidator])
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

    @cached_property
    def stoken(self):
        return self.content.uid


def chunk_directory_path(instance, filename):
    item = instance.item
    col = item.collection
    user_id = col.owner.id
    item_uid = item.uid or 'main'
    return Path('user_{}'.format(user_id), col.uid, item_uid, instance.uid)


class CollectionItemChunk(models.Model):
    uid = models.CharField(db_index=True, blank=False, null=False,
                           max_length=44, validators=[Base64Url256BitValidator])
    item = models.ForeignKey(CollectionItem, related_name='chunks', on_delete=models.CASCADE)
    chunkFile = models.FileField(upload_to=chunk_directory_path, max_length=150, unique=True)

    def __str__(self):
        return self.uid


class CollectionItemRevision(models.Model):
    uid = models.CharField(db_index=True, unique=True, blank=False, null=False,
                           max_length=44, validators=[Base64Url256BitValidator])
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


class CollectionInvitation(models.Model):
    uid = models.CharField(db_index=True, blank=False, null=False,
                           max_length=44, validators=[Base64Url256BitValidator])
    version = models.PositiveSmallIntegerField(default=1)
    fromMember = models.ForeignKey(CollectionMember, on_delete=models.CASCADE)
    # FIXME: make sure to delete all invitations for the same collection once one is accepted

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


class UserInfo(models.Model):
    owner = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, primary_key=True)
    version = models.PositiveSmallIntegerField(default=1)
    pubkey = models.BinaryField(editable=True, blank=False, null=False)
    salt = models.BinaryField(editable=True, blank=False, null=False)

    def __str__(self):
        return "UserInfo<{}>".format(self.owner)
