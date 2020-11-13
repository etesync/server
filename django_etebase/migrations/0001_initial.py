# Generated by Django 3.0.3 on 2020-05-13 13:01

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import django_etebase.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Collection",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "uid",
                    models.CharField(
                        db_index=True,
                        max_length=44,
                        validators=[
                            django.core.validators.RegexValidator(message="Not a valid UID", regex="[a-zA-Z0-9]")
                        ],
                    ),
                ),
                ("version", models.PositiveSmallIntegerField()),
                ("owner", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={"unique_together": {("uid", "owner")},},
        ),
        migrations.CreateModel(
            name="CollectionItem",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "uid",
                    models.CharField(
                        db_index=True,
                        max_length=44,
                        null=True,
                        validators=[
                            django.core.validators.RegexValidator(message="Not a valid UID", regex="[a-zA-Z0-9]")
                        ],
                    ),
                ),
                ("version", models.PositiveSmallIntegerField()),
                ("encryptionKey", models.BinaryField(editable=True, null=True)),
                (
                    "collection",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="items",
                        to="django_etebase.Collection",
                    ),
                ),
            ],
            options={"unique_together": {("uid", "collection")},},
        ),
        migrations.CreateModel(
            name="CollectionItemChunk",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "uid",
                    models.CharField(
                        db_index=True,
                        max_length=44,
                        validators=[
                            django.core.validators.RegexValidator(
                                message="Expected a 256bit base64url.", regex="^[a-zA-Z0-9\\-_]{43}$"
                            )
                        ],
                    ),
                ),
                (
                    "chunkFile",
                    models.FileField(max_length=150, unique=True, upload_to=django_etebase.models.chunk_directory_path),
                ),
                (
                    "item",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="chunks",
                        to="django_etebase.CollectionItem",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="CollectionItemRevision",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "uid",
                    models.CharField(
                        db_index=True,
                        max_length=44,
                        unique=True,
                        validators=[
                            django.core.validators.RegexValidator(
                                message="Expected a 256bit base64url.", regex="^[a-zA-Z0-9\\-_]{43}$"
                            )
                        ],
                    ),
                ),
                ("meta", models.BinaryField(editable=True)),
                ("current", models.BooleanField(db_index=True, default=True, null=True)),
                ("deleted", models.BooleanField(default=False)),
                (
                    "item",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="revisions",
                        to="django_etebase.CollectionItem",
                    ),
                ),
            ],
            options={"unique_together": {("item", "current")},},
        ),
        migrations.CreateModel(
            name="RevisionChunkRelation",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "chunk",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="revisions_relation",
                        to="django_etebase.CollectionItemChunk",
                    ),
                ),
                (
                    "revision",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="chunks_relation",
                        to="django_etebase.CollectionItemRevision",
                    ),
                ),
            ],
            options={"ordering": ("id",),},
        ),
        migrations.CreateModel(
            name="CollectionMember",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("encryptionKey", models.BinaryField(editable=True)),
                (
                    "accessLevel",
                    models.CharField(
                        choices=[("adm", "Admin"), ("rw", "Read Write"), ("ro", "Read Only")],
                        default="ro",
                        max_length=3,
                    ),
                ),
                (
                    "collection",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="members",
                        to="django_etebase.Collection",
                    ),
                ),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={"unique_together": {("user", "collection")},},
        ),
    ]
