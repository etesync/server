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
    mainItem = models.OneToOneField('CollectionItem', related_name='of_collection', on_delete=models.PROTECT)

    class Meta:
        unique_together = ('uid', 'owner')

    def __str__(self):
        return self.uid

    @cached_property
    def content(self):
        return self.mainItem.content


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


def chunk_directory_path(instance, filename):
    item = instance.item
    col = item.collection
    user_id = col.owner.id
    return Path('user_{}'.format(user_id), col.uid, item.uid, instance.uid)


class CollectionItemChunk(models.Model):
    uid = models.CharField(db_index=True, blank=False, null=False,
                           max_length=44, validators=[Base64Url256BitValidator])
    item = models.ForeignKey(CollectionItem, related_name='chunks', on_delete=models.CASCADE)
    order = models.CharField(max_length=100, blank=False, null=False)
    chunkFile = models.FileField(upload_to=chunk_directory_path, max_length=150, unique=True)

    class Meta:
        unique_together = ('item', 'order')
        ordering = ('item', 'order')

    def __str__(self):
        return self.uid


class CollectionItemRevision(models.Model):
    uid = models.CharField(db_index=True, unique=True, blank=False, null=False,
                           max_length=44, validators=[Base64Url256BitValidator])
    item = models.ForeignKey(CollectionItem, related_name='revisions', on_delete=models.CASCADE)
    meta = models.BinaryField(editable=True, blank=True, null=True)
    chunks = models.ManyToManyField(CollectionItemChunk, related_name='items')
    current = models.BooleanField(db_index=True, default=True, null=True)
    deleted = models.BooleanField(default=False)

    class Meta:
        unique_together = ('item', 'current')

    def __str__(self):
        return '{} {} current={}'.format(self.uid, self.item.uid, self.current)


class CollectionMember(models.Model):
    class AccessLevels(models.TextChoices):
        ADMIN = 'adm'
        READ_WRITE = 'rw'
        READ_ONLY = 'ro'

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
