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


class CollectionItem(models.Model):
    uid = models.CharField(db_index=True, blank=False, null=False,
                           max_length=44, validators=[UidValidator])
    version = models.PositiveSmallIntegerField()
    encryptionKey = models.BinaryField(editable=True, blank=False, null=False)
    collection = models.ForeignKey(Collection, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('uid', 'collection')

    @cached_property
    def content(self):
        return self.snapshots.get(current=True)

    def __str__(self):
        return self.uid


class CollectionItemSnapshot(models.Model):
    item = models.ForeignKey(CollectionItem, related_name='snapshots', on_delete=models.CASCADE)
    current = models.BooleanField(default=True)
    chunkHmac = models.CharField(max_length=50, blank=False, null=False)

    class Meta:
        unique_together = ('item', 'current')

    def __str__(self):
        return "{}, current={}".format(self.item.uid, self.current)


class CollectionItemChunk(models.Model):
    uid = models.CharField(db_index=True, blank=False, null=False,
                           max_length=44, validators=[UidValidator])
    itemSnapshot = models.ForeignKey(CollectionItemSnapshot, related_name='chunks', null=True, on_delete=models.SET_NULL)
    order = models.CharField(max_length=100, blank=False, null=False)

    class Meta:
        # unique_together = ('itemSnapshot', 'order') # Currently off because we set the item snapshot to null on deletion
        ordering = ['order']

    def __str__(self):
        return self.uid
