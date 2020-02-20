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


UidValidator = RegexValidator(regex=r'[a-zA-Z0-9\-_=]{44}', message='Not a valid UID. Expected a 256bit base64url.')


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
    def current_items(self):
        return self.items.filter(current=True)


class CollectionItem(models.Model):
    uid = models.CharField(db_index=True, blank=False, null=False,
                           max_length=44, validators=[UidValidator])
    version = models.PositiveSmallIntegerField()
    encryptionKey = models.BinaryField(editable=True, blank=False, null=False)
    collection = models.ForeignKey(Collection, related_name='items', on_delete=models.CASCADE)
    hmac = models.CharField(max_length=50, blank=False, null=False)
    current = models.BooleanField(db_index=True, default=True)

    class Meta:
        unique_together = ('uid', 'collection')

    def __str__(self):
        return self.uid


def chunk_directory_path(instance, filename):
    col = instance.itemSnapshot.item.collection
    user_id = col.owner.id
    return Path('user_{}'.format(user_id), col.uid, instance.uid)


class CollectionItemChunk(models.Model):
    uid = models.CharField(db_index=True, blank=False, null=False,
                           max_length=44, validators=[UidValidator])
    items = models.ManyToManyField(CollectionItem, related_name='chunks')
    order = models.CharField(max_length=100, blank=False, null=False)
    # We probably just want to implement this manually because we can have more than one pointing to a file. chunkFile = models.FileField(upload_to=chunk_directory_path)

    class Meta:
        ordering = ['order']

    def __str__(self):
        return self.uid
