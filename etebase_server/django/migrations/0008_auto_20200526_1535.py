# Generated by Django 3.0.3 on 2020-05-26 15:35

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
from etebase_server.django.models import generate_stoken_uid


class Migration(migrations.Migration):

    dependencies = [
        ("django_etebase", "0007_auto_20200526_1336"),
    ]

    operations = [
        migrations.CreateModel(
            name="Stoken",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "uid",
                    models.CharField(
                        db_index=True,
                        default=generate_stoken_uid,
                        max_length=43,
                        unique=True,
                        validators=[
                            django.core.validators.RegexValidator(
                                message="Expected a base64url.", regex="^[a-zA-Z0-9\\-_]{42,43}$"
                            )
                        ],
                    ),
                ),
            ],
        ),
        migrations.AddField(
            model_name="collectionitemrevision",
            name="stoken",
            field=models.OneToOneField(
                null=True, on_delete=django.db.models.deletion.PROTECT, to="django_etebase.Stoken"
            ),
        ),
    ]
