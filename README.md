<p align="center">
  <img width="120" src="icon.svg" />
  <h1 align="center">EteSync - Secure Data Sync</h1>
</p>

A skeleton app for running your own [EteSync](https://www.etesync.com) server

# Installation

Before installing the EteSync server make sure you install `virtualenv` (for **Python 3**):

* Arch Linux: `pacman -S python-virtualenv`
* Debian/Ubuntu: `apt-get install python3-virtualenv`

Then just clone the git repo and set up this app:

```
git clone https://github.com/etesync/server-skeleton.git

cd server-skeleton

# Set up the environment and deps
virtualenv -p python3 venv  # If doesn't work, try: virtualenv3 venv
source venv/bin/activate

pip install -r requirements.txt
```

If you are familiar with Django you can just edit the [settings file](etesync_server/settings.py)
according to the [Django deployment checklist](https://docs.djangoproject.com/en/1.11/howto/deployment/checklist)
if you are not, we also provide a simple [configuration file](etesync-server.ini)
for easy deployment which you can use. You can either edit the provided file or
create one in `/etc/etesync-server`.

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

Now you can initialise our django app

```
./manage.py migrate
```

And you are done! You can now run the debug server just to see everything works as expected by running:

```
./manage.py runserver 0.0.0.0:8000
```

Using the debug server in production is not recommended, so please read the following section for a proper deployment.

# Production deployment

EteSync is based on Django so you should :
  * either follow the instructions of the Django project [here](https://docs.djangoproject.com/en/2.2/howto/deployment/wsgi/).
  * either/or follow the instructions from uwsgi [here](http://uwsgi-docs.readthedocs.io/en/latest/tutorials/Django_and_nginx.html).

The webserver should also be configured to serve EteSync using TLS.

There are more details about a proper production setup in the [wiki](https://github.com/etesync/server-skeleton/wiki).
  
# Usage

Create yourself an admin user:

```
./manage.py createsuperuser
```

At this stage you can either just use the admin user, or better yet, go to: ```www.your-etesync-install.com/admin```
and create a non-privileged user that you can use.

That's it!

Now all that's left is to open the EteSync app, add an account, and set your custom server address under the "advance" section.

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

# Supporting EteSync

Please consider registering an account even if you self-host in order to support the development of EteSync, or help by spreading the word.
