A skeleton app for running your own [EteSync](https://www.etesync.com) server

# Installation

To setup your own EteSync server based on the git version just clone this
git repository and set up the django app:

```
git clone https://github.com/etesync/server-skeleton.git

cd server-skeleton

# Set up the environment and deps
virtualenv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

Edit the [settings file](etesync_server/settings.py). Please refer to the
[Django deployment
checklist](https://docs.djangoproject.com/en/1.10/howto/deployment/checklist/)
for full instructions on how to configure a Django app for production. Some
particular settings that should be edited are:
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

And you are done! You can now either run the debug server just to see everything works as expected by running:

```
./manage.py runserver 0.0.0.0:8000
```

Using the debug server in production is not recommended, so you should configure your webserver to serve
etesync (with TLS). An example on how to do so with nginx can be found [here](http://uwsgi-docs.readthedocs.io/en/latest/tutorials/Django_and_nginx.html).

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

Inside the virtualenv, run `pip install -U -r requirements.txt` to update
dependencies to latest compatible versions of Django and
djangorestframework (it will only update to latest patch level which should
be API-compatible).

# Supporting EteSync

Please consider registering an account even if you self-host in order to support the development of EteSync, or help by spreading the word.
