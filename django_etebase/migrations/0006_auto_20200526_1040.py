# Generated by Django 3.0.3 on 2020-05-26 10:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("django_etebase", "0005_auto_20200526_1021"),
    ]

    operations = [
        migrations.AddField(
            model_name="userinfo",
            name="encryptedSeckey",
            field=models.BinaryField(default=b"", editable=True),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="userinfo",
            name="pubkey",
            field=models.BinaryField(default=b"", editable=True),
            preserve_default=False,
        ),
    ]
