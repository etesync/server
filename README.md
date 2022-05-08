<p align="center">
  <img width="120" src="icon.svg" />
  <h1 align="center">Etebase - Encrypt Everything</h1>
</p>

An [Etebase](https://www.etebase.com) (EteSync 2.0) server so you can run your own.

[![Chat with us](https://img.shields.io/badge/chat-IRC%20|%20Matrix%20|%20Web-blue.svg)](https://www.etebase.com/community-chat/)

# Installation

## Requirements

Etebase requires Python 3.7 or newer and has a few Python dependencies (listed in `requirements.in/base.txt`).

## From source

Before installing the Etebase server make sure you install `virtualenv` (for **Python 3**):

* Arch Linux: `pacman -S python-virtualenv`
* Debian/Ubuntu: `apt-get install python3-virtualenv`
* Mac/Windows (WSL)/Other Linux: install virtualenv or just skip the instructions mentioning virtualenv.

Then just clone the git repo and set up this app:

```
git clone https://github.com/etesync/server.git etebase

cd etebase

# Set up the environment and deps
virtualenv -p python3 .venv  # If doesn't work, try: virtualenv3 .venv
source .venv/bin/activate

pip install -r requirements.txt
```

# Configuration

If you are familiar with Django you can just edit the [settings file](etebase_server/settings.py)
according to the [Django deployment checklist](https://docs.djangoproject.com/en/dev/howto/deployment/checklist/).
If you are not, we also provide a simple [configuration file](etebase-server.ini.example) for easy deployment which you can use.
To use the easy configuration file rename it to `etebase-server.ini` and place it either at the root of this repository or in `/etc/etebase-server`.

There is also a [wikipage](https://github.com/etesync/server/wiki/Basic-Setup-Etebase-(EteSync-v2)) detailing this basic setup.

Some particular settings that should be edited are:
  * [`ALLOWED_HOSTS`](https://docs.djangoproject.com/en/dev/ref/settings/#std:setting-ALLOWED_HOSTS)
    -- this is the list of host/domain names or addresses on which the app
will be served. For example: `etebase.example.com`
  * [`DEBUG`](https://docs.djangoproject.com/en/dev/ref/settings/#debug)
    -- handy for debugging, set to `False` for production
  * [`MEDIA_ROOT`](https://docs.djangoproject.com/en/dev/ref/settings/#media-root)
    -- the path to the directory that will hold user data.
  * [`SECRET_KEY`](https://docs.djangoproject.com/en/dev/ref/settings/#std:setting-SECRET_KEY)
    -- an ephemeral secret used for various cryptographic signing and token
generation purposes. See below for how default configuration of
`SECRET_KEY` works for this project.

Now you can initialise our django app.

```
./manage.py migrate
```

And you are done! You can now run the debug server just to see everything works as expected by running:

```
uvicorn etebase_server.asgi:application --host 0.0.0.0 --port 8000
```

Using the debug server in production is not recommended, so please read the following section for a proper deployment.

# Production deployment

There are more details about a proper production setup using uvicorn and Nginx in the [wiki](https://github.com/etesync/server/wiki/Production-setup-using-Nginx).

The webserver should also be configured to serve Etebase using TLS.
A guide for doing so can be found in the [wiki](https://github.com/etesync/server/wiki/Setup-HTTPS-for-Etebase) as well.

The Etebase server needs to be aware of the URL it's been served as, so make sure to forward the `Host` header to the server if using a reverse proxy. For example, you would need to use the following directive in nginx: `proxy_set_header Host $host;`.

# Data locations and backups

The server stores user data in two different locations that need to be backed up:
1. The database - how to backup depends on which database you use.
2. The `MEDIA_ROOT` - the path where user data is stored.

# Usage

Create yourself an admin user:

```
./manage.py createsuperuser
```

At this stage you need to create accounts to be used with the EteSync apps. To do that, please go to:
`www.your-etesync-install.com/admin` or use CLI `./manage.py createuser <username>` and create a new user to be used with the service. No need to set
a password, as Etebase uses a zero-knowledge proof for authentication, so the user will just create
a password when creating the account from the apps.

After this user has been created, you can use any of the EteSync apps to signup (or login) with the same username and
email in order to set up the account. The password used at that point will be used to setup the account.
Don't forget to set your custom server address under "Advanced".

# `SECRET_KEY` and `secret.txt`

The default configuration creates a file “`secret.txt`” in the project’s
base directory, which is used as the value of the Django `SECRET_KEY`
setting. You can revoke this key by deleting the `secret.txt` file and the
next time the app is run, a new one will be generated. Make sure you keep
the `secret.txt` file secret (e.g. don’t accidentally commit it to version
control). However, backing it up is okay, and it makes it easier to restore
the database to a new EteSync server, but it's not essential. If you want to
change to a more secure system for storing secrets, edit `etesync_server/settings.py`
and implement your own method for setting `SECRET_KEY` (remove the line
where it uses the `get_secret_from_file` function).  Read the Django docs
for more information about the `SECRET_KEY` and its uses.

# Updating

## Updating from version 0.5.0 onwards

First, run `git pull --rebase` to update this repository.
Then, inside the virtualenv:
1. Run `pip install -U -r requirements.txt` to update the dependencies.
2. Run `python manage.py migrate` to perform database migrations.

You can now restart the server.

## Updating from version 0.5.0 or before

The 0.5.0 release marks the change to the EteSync 2.0 protocol. EteSync 2.0 accounts are substantially different to 1.0 accounts, and require additional upgrade steps. In addition, the servers are incompatible, so 0.5.0 requires a fresh installation.

Here are the update steps:
1. Chose any of the [the migration tools](https://www.etesync.com/user-guide/migrate-v2/) and make sure the underlying apps are up to date with all of your data. So for example, if you are using the Android client, make sure to sync before commencing.
2. Install the 0.5.0 version to a new path (you can't reuse the same database).
3. Run the 0.5.0 account and create the appropriate users as described in the installation/upgrade steps above.
4. Run the migration tool to migrate all of your data.
5. Add your new EteSync 2.0 accounts to all of your devices.

# Testing

Docker images named `etesync/test-server:<version>` and `:latest` are available for testing etesync clients.
This docker image starts a server on port 3735 that supports user signup (without email confirmation), is in debug mode (thus supporting the reset endpoint), and stores its data locally.
It is in no way suitable for production usage, but is able to start up quickly and makes a good component of CI for etesync clients and users of those clients.

# User signup

Instead of having to create Django users manually when signup up Etebase users, it is also possible to allow automatic signup.
For example, this makes sense when putting an Etebase server in production.
However, this does come with the added risk that everybody with access to your server will be able to sign up.

In order to set it up, comment out the line `ETEBASE_CREATE_USER_FUNC = "django_etebase.utils.create_user_blocked"` in `server/settings.py` and restart your Etebase server.

# License

Etebase is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License version 3 as published by the Free Software Foundation. See the [LICENSE](./LICENSE) for more information.

A quick summary can be found [on tldrlegal](https://tldrlegal.com/license/gnu-affero-general-public-license-v3-(agpl-3.0)). Though in even simpler terms (not part of the license, and not legal advice): you can use it in however way you want, including self-hosting and commercial offerings as long as you release the code to any modifications you have made to the server software (clients are not affected).

## Commercial licensing

For commercial licensing options, contact license@etebase.com

# Financially Supporting Etebase

Please consider registering an account even if you self-host in order to support the development of Etebase, or visit the [contribution](https://www.etesync.com/contribute/) for more information on how to support the service.

Become a financial contributor and help us sustain our community!

## Supporters ($20 / month)

[![jzacsh](https://github.com/jzacsh.png?size=80)](https://github.com/jzacsh)

## Contributors ($10 / month)

[![ilovept](https://github.com/ilovept.png?size=40)](https://github.com/ilovept)
[![ryanleesipes](https://github.com/ryanleesipes.png?size=40)](https://github.com/ryanleesipes)
[![DanielG](https://github.com/DanielG.png?size=40)](https://github.com/DanielG)
