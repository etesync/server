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

Set the django ```SECRET_KEY``` and ```ALLOWED_HOSTS``` in [the settings file](etesync_server/settings.py).
For more information on these please refer to the [django deployment checklist](https://docs.djangoproject.com/en/1.10/howto/deployment/checklist/).

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

# Supporting EteSync

Please consider registering an account even if you self-host in order to support the development of EteSync, or help by spreading the word.
