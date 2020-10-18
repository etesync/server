<p align="center">
  <img width="120" src="icon.svg" />
  <h1 align="center">Etebase - Encrypt Everything</h1>
</p>

A skeleton app for running your own [Etebase](https://www.etebase.com) (EteSync 2.0) server.

# Installation

## From source

Before installing the Etebase server make sure you install `virtualenv` (for **Python 3**):

* Arch Linux: `pacman -S python-virtualenv`
* Debian/Ubuntu: `apt-get install python3-virtualenv`
* Mac/Windows/Other Linux: install virtualenv or just skip the instructions mentioning virtualenv.

Then just clone the git repo and set up this app:

```
git clone https://github.com/etesync/server.git etebase

cd etebase
git checkout etebase

# Set up the environment and deps
virtualenv -p python3 venv  # If doesn't work, try: virtualenv3 venv
source venv/bin/activate

pip install -r requirements.txt
```

# Configuration

If you are familiar with Django you can just edit the [settings file](etesync_server/settings.py)
according to the [Django deployment checklist](https://docs.djangoproject.com/en/dev/howto/deployment/checklist/).
If you are not, we also provide a simple [configuration file](https://github.com/etesync/server/blob/etebase/etebase-server.ini.example) for easy deployment which you can use.
To use the easy configuration file rename it to `etebase-server.ini` and place it either at the root of this repository or in `/etc/etebase-server`.

There is also a [wikipage](https://github.com/etesync/server/wiki/Basic-Setup-Etebase-(EteSync-v2)) detailing this basic setup.

Some particular settings that should be edited are:
  * [`ALLOWED_HOSTS`](https://docs.djangoproject.com/en/1.11/ref/settings/#std:setting-ALLOWED_HOSTS)
    -- this is the list of host/domain names or addresses on which the app
will be served
  * [`DEBUG`](https://docs.djangoproject.com/en/1.11/ref/settings/#debug)
    -- handy for debugging, set to `False` for production
  * [`SECRET_KEY`](https://docs.djangoproject.com/en/1.11/ref/settings/#std:setting-SECRET_KEY)
    -- an ephemeral secret used for various cryptographic signing and token
generation purposes. See below for how default configuration of
`SECRET_KEY` works for this project.

Now you can initialise our django app.

```
./manage.py migrate
```

And you are done! You can now run the debug server just to see everything works as expected by running:

```
./manage.py runserver 0.0.0.0:8000
```

Using the debug server in production is not recommended, so please read the following section for a proper deployment.

# Production deployment

There are more details about a proper production setup using Daphne and Nginx in the [wiki](https://github.com/etesync/server/wiki/Production-setup-using-Daphne-and-Nginx).

Etebase is based on Django so you should refer to one of the following
  * The instructions of the Django project [here](https://docs.djangoproject.com/en/2.2/howto/deployment/wsgi/).
  * Instructions from uwsgi [here](http://uwsgi-docs.readthedocs.io/en/latest/tutorials/Django_and_nginx.html).

The webserver should also be configured to serve Etebase using TLS.
A guide for doing so can be found in the [wiki](https://github.com/etesync/server/wiki/Setup-HTTPS-for-Etebase) as well.

# Usage

Create yourself an admin user:

```
./manage.py createsuperuser
```

At this stage you need to create accounts to be used with the EteSync apps. To do that, please go to:
`www.your-etesync-install.com/admin` and create a new user to be used with the service.

After this user has been created, you can use any of the EteSync apps to signup (not login!) with the same username and
email in order to set up the account. Please make sure to click "advance" and set your customer server address when you
do.

# `SECRET_KEY` and `secret.txt`

The default configuration creates a file “`secret.txt`” in the project’s
base directory, which is used as the value of the Django `SECRET_KEY`
setting. You can revoke this key by deleting the `secret.txt` file and the
next time the app is run, a new one will be generated. Make sure you keep
the `secret.txt` file secret (don’t accidentally commit it to version
control, exclude it from your backups, etc.). If you want to change to a
more secure system for storing secrets, edit `etesync_server/settings.py`
and implement your own method for setting `SECRET_KEY` (remove the line
where it uses the `get_secret_from_file` function).  Read the Django docs
for more information about the `SECRET_KEY` and its uses.

# Updating

First, run `git pull --rebase` to update this repository.
Then, inside the virtualenv:
1. Run `pip install -U -r requirements.txt` to update the dependencies.
2. Run `python manage.py migrate` to perform database migrations.

You can now restart the server.

# Supporting Etebase

Please consider registering an account even if you self-host in order to support the development of Etebase, or visit the [contribution](https://www.etesync.com/contribute/) for more information on how to support the service.
