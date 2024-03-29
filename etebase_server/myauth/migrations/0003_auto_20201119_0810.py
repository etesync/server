# Generated by Django 3.1.1 on 2020-11-19 08:10

from django.db import migrations, models
import etebase_server.myauth.models as myauth_models


class Migration(migrations.Migration):

    dependencies = [
        ("myauth", "0002_auto_20200515_0801"),
    ]

    operations = [
        migrations.AlterModelManagers(
            name="user",
            managers=[
                ("objects", myauth_models.UserManager()),
            ],
        ),
        migrations.AlterField(
            model_name="user",
            name="first_name",
            field=models.CharField(blank=True, max_length=150, verbose_name="first name"),
        ),
        migrations.AlterField(
            model_name="user",
            name="username",
            field=models.CharField(
                error_messages={"unique": "A user with that username already exists."},
                help_text="Required. 150 characters or fewer. Letters, digits and ./-/_ only.",
                max_length=150,
                unique=True,
                validators=[myauth_models.UnicodeUsernameValidator()],
                verbose_name="username",
            ),
        ),
    ]
