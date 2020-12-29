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

import typing as t
from pathlib import Path

from django.db import models, transaction
from django.conf import settings
from django.core.validators import RegexValidator
from django.db.models import Max, Value as V
from django.db.models.functions import Coalesce, Greatest
from django.utils.functional import cached_property
from django.utils.crypto import get_random_string

from . import app_settings


UidValidator = RegexValidator(regex=r"^[a-zA-Z0-9\-_]{20,}$", message="Not a valid UID")


def stoken_annotation_builder(stoken_id_fields: t.List[str]):
    aggr_fields = [Coalesce(Max(field), V(0)) for field in stoken_id_fields]
    return Greatest(*aggr_fields) if len(aggr_fields) > 1 else aggr_fields[0]


class CollectionType(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    uid = models.BinaryField(editable=True, blank=False, null=False, db_index=True, unique=True)

    objects: models.manager.BaseManager["CollectionType"]


class Collection(models.Model):
    main_item = models.OneToOneField("CollectionItem", related_name="parent", null=True, on_delete=models.SET_NULL)
    # The same as main_item.uid, we just also save it here so we have DB constraints for uniqueness (and efficiency)
    uid = models.CharField(db_index=True, unique=True, blank=False, max_length=43, validators=[UidValidator])
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    stoken_annotation = stoken_annotation_builder(["items__revisions__stoken", "members__stoken"])

    objects: models.manager.BaseManager["Collection"]

    def __str__(self):
        return self.uid

    @property
    def content(self) -> "CollectionItemRevision":
        assert self.main_item is not None
        return self.main_item.content

    @property
    def etag(self) -> str:
        return self.content.uid

    @cached_property
    def stoken(self) -> str:
        stoken_id = (
            self.__class__.objects.filter(main_item=self.main_item)
            .annotate(max_stoken=self.stoken_annotation)
            .values("max_stoken")
            .first()["max_stoken"]
        )

        if stoken_id == 0:
            raise Exception("stoken is None. Should never happen")

        return Stoken.objects.get(id=stoken_id).uid


class CollectionItem(models.Model):
    uid = models.CharField(db_index=True, blank=False, max_length=43, validators=[UidValidator])
    collection = models.ForeignKey(Collection, related_name="items", on_delete=models.CASCADE)
    version = models.PositiveSmallIntegerField()
    encryptionKey = models.BinaryField(editable=True, blank=False, null=True)

    stoken_annotation = stoken_annotation_builder(["revisions__stoken"])

    objects: models.manager.BaseManager["CollectionItem"]

    class Meta:
        unique_together = ("uid", "collection")

    def __str__(self):
        return "{} {}".format(self.uid, self.collection.uid)

    @cached_property
    def content(self) -> "CollectionItemRevision":
        return self.revisions.get(current=True)

    @property
    def etag(self) -> str:
        return self.content.uid


def chunk_directory_path(instance: "CollectionItemChunk", filename: str) -> Path:
    custom_func = app_settings.CHUNK_PATH_FUNC
    if custom_func is not None:
        return custom_func(instance, filename)

    col: Collection = instance.collection
    user_id: int = col.owner.id
    uid_prefix: str = instance.uid[:2]
    uid_rest: str = instance.uid[2:]
    return Path("user_{}".format(user_id), col.uid, uid_prefix, uid_rest)


class CollectionItemChunk(models.Model):
    uid = models.CharField(db_index=True, blank=False, null=False, max_length=60, validators=[UidValidator])
    collection = models.ForeignKey(Collection, related_name="chunks", on_delete=models.CASCADE)
    chunkFile = models.FileField(upload_to=chunk_directory_path, max_length=150, unique=True)

    objects: models.manager.BaseManager["CollectionItemChunk"]

    def __str__(self):
        return self.uid

    class Meta:
        unique_together = ("collection", "uid")


def generate_stoken_uid():
    return get_random_string(32, allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


class Stoken(models.Model):
    id: int
    uid = models.CharField(
        db_index=True,
        unique=True,
        blank=False,
        null=False,
        default=generate_stoken_uid,
        max_length=43,
        validators=[UidValidator],
    )

    objects: models.manager.BaseManager["Stoken"]


class CollectionItemRevision(models.Model):
    stoken = models.OneToOneField(Stoken, on_delete=models.PROTECT)
    uid = models.CharField(
        db_index=True, unique=True, blank=False, null=False, max_length=43, validators=[UidValidator]
    )
    item = models.ForeignKey(CollectionItem, related_name="revisions", on_delete=models.CASCADE)
    meta = models.BinaryField(editable=True, blank=False, null=False)
    current = models.BooleanField(db_index=True, default=True, null=True)
    deleted = models.BooleanField(default=False)

    objects: models.manager.BaseManager["CollectionItemRevision"]

    class Meta:
        unique_together = ("item", "current")

    def __str__(self):
        return "{} {} current={}".format(self.uid, self.item.uid, self.current)


class RevisionChunkRelation(models.Model):
    chunk = models.ForeignKey(CollectionItemChunk, related_name="revisions_relation", on_delete=models.CASCADE)
    revision = models.ForeignKey(CollectionItemRevision, related_name="chunks_relation", on_delete=models.CASCADE)

    objects: models.manager.BaseManager["RevisionChunkRelation"]

    class Meta:
        ordering = ("id",)


class AccessLevels(models.IntegerChoices):
    READ_ONLY = 0
    ADMIN = 1
    READ_WRITE = 2


class CollectionMember(models.Model):
    stoken = models.OneToOneField(Stoken, on_delete=models.PROTECT, null=True)
    collection = models.ForeignKey(Collection, related_name="members", on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    encryptionKey = models.BinaryField(editable=True, blank=False, null=False)
    collectionType = models.ForeignKey(CollectionType, on_delete=models.PROTECT, null=True)
    accessLevel = models.IntegerField(
        choices=AccessLevels.choices,
        default=AccessLevels.READ_ONLY,
    )

    stoken_annotation = stoken_annotation_builder(["stoken"])

    objects: models.manager.BaseManager["CollectionMember"]

    class Meta:
        unique_together = ("user", "collection")

    def __str__(self):
        return "{} {}".format(self.collection.uid, self.user)

    def revoke(self):
        with transaction.atomic():
            CollectionMemberRemoved.objects.update_or_create(
                collection=self.collection,
                user=self.user,
                defaults={
                    "stoken": Stoken.objects.create(),
                },
            )

            self.delete()


class CollectionMemberRemoved(models.Model):
    stoken = models.OneToOneField(Stoken, on_delete=models.PROTECT, null=True)
    collection = models.ForeignKey(Collection, related_name="removed_members", on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    objects: models.manager.BaseManager["CollectionMemberRemoved"]

    class Meta:
        unique_together = ("user", "collection")

    def __str__(self):
        return "{} {}".format(self.collection.uid, self.user)


class CollectionInvitation(models.Model):
    uid = models.CharField(db_index=True, blank=False, null=False, max_length=43, validators=[UidValidator])
    version = models.PositiveSmallIntegerField(default=1)
    fromMember = models.ForeignKey(CollectionMember, on_delete=models.CASCADE)
    # FIXME: make sure to delete all invitations for the same collection once one is accepted
    # Make sure to not allow invitations if already a member

    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="incoming_invitations", on_delete=models.CASCADE)
    signedEncryptionKey = models.BinaryField(editable=False, blank=False, null=False)
    accessLevel = models.IntegerField(
        choices=AccessLevels.choices,
        default=AccessLevels.READ_ONLY,
    )

    objects: models.manager.BaseManager["CollectionInvitation"]

    class Meta:
        unique_together = ("user", "fromMember")

    def __str__(self):
        return "{} {}".format(self.fromMember.collection.uid, self.user)

    @cached_property
    def collection(self) -> Collection:
        return self.fromMember.collection


class UserInfo(models.Model):
    owner = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, primary_key=True)
    version = models.PositiveSmallIntegerField(default=1)
    loginPubkey = models.BinaryField(editable=True, blank=False, null=False)
    pubkey = models.BinaryField(editable=True, blank=False, null=False)
    encryptedContent = models.BinaryField(editable=True, blank=False, null=False)
    salt = models.BinaryField(editable=True, blank=False, null=False)

    objects: models.manager.BaseManager["UserInfo"]

    def __str__(self):
        return "UserInfo<{}>".format(self.owner)
