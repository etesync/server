"""
Django settings for etebase_server project.

Generated by 'django-admin startproject' using Django 3.0.3.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.0/ref/settings/
"""

import os
import configparser
from .utils import get_secret_from_file

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

AUTH_USER_MODEL = "myauth.User"


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
# See secret.py for how this is generated; uses a file 'secret.txt' in the root
# directory
SECRET_FILE = os.path.join(BASE_DIR, "secret.txt")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

# Database
# https://docs.djangoproject.com/en/2.0/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("ETEBASE_DB_PATH", os.path.join(BASE_DIR, "db.sqlite3")),
    }
}

DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'

# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "myauth.apps.MyauthConfig",
    "django_etebase.apps.DjangoEtebaseConfig",
    "django_etebase.token_auth.apps.TokenAuthConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "etebase_server.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, "templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "etebase_server.wsgi.application"


# Password validation
# https://docs.djangoproject.com/en/3.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/

STATIC_URL = "/static/"
STATIC_ROOT = os.environ.get("DJANGO_STATIC_ROOT", os.path.join(BASE_DIR, "static"))

MEDIA_ROOT = os.environ.get("DJANGO_MEDIA_ROOT", os.path.join(BASE_DIR, "media"))
MEDIA_URL = "/user-media/"


# Define where to find configuration files
config_locations = [
    os.environ.get("ETEBASE_EASY_CONFIG_PATH", ""),
    "etebase-server.ini",
    "/etc/etebase-server/etebase-server.ini",
]

# Use config file if present
if any(os.path.isfile(x) for x in config_locations):
    config = configparser.ConfigParser()
    config.read(config_locations)

    section = config["global"]

    SECRET_FILE = section.get("secret_file", SECRET_FILE)
    STATIC_ROOT = section.get("static_root", STATIC_ROOT)
    STATIC_URL = section.get("static_url", STATIC_URL)
    MEDIA_ROOT = section.get("media_root", MEDIA_ROOT)
    MEDIA_URL = section.get("media_url", MEDIA_URL)
    LANGUAGE_CODE = section.get("language_code", LANGUAGE_CODE)
    TIME_ZONE = section.get("time_zone", TIME_ZONE)
    DEBUG = section.getboolean("debug", DEBUG)

    if "redis_uri" in section:
        ETEBASE_REDIS_URI = section.get("redis_uri")

    if "allowed_hosts" in config:
        ALLOWED_HOSTS = [y for x, y in config.items("allowed_hosts")]

    if "database" in config:
        DATABASES = {"default": {x.upper(): y for x, y in config.items("database")}}

    if "database-options" in config:
        DATABASES["default"]["OPTIONS"] = config["database-options"]

ETEBASE_CREATE_USER_FUNC = "django_etebase.utils.create_user_blocked"

# Efficient file streaming (for large files)
SENDFILE_BACKEND = "etebase_fastapi.sendfile.backends.simple"
SENDFILE_ROOT = MEDIA_ROOT

# Make an `etebase_server_settings` module available to override settings.
try:
    from etebase_server_settings import *
except ImportError:
    pass

if "SECRET_KEY" not in locals():
    SECRET_KEY = get_secret_from_file(SECRET_FILE)
