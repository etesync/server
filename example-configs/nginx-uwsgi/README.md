# Running `etebase` under `nginx` and `uwsgi`

This configuration assumes that etebase server has been installed in the home folder of a non privileged user
called `EtebaseUser` following the instructions in <https://github.com/etesync/server>. Also that static
files have been collected at `/srv/http/etebase_server` by running the following commands:

```shell
sudo mkdir -p /srv/http/etebase_server/static
sudo chown -R EtebaseUser /srv/http/etebase_server
sudo su EtebaseUser
cd /path/to/etebase
ln -s /srv/http/etebase_server/static static
./manage.py collectstatic
```

It is also assumed that `nginx` and `uwsgi` have been installed system wide by `root`, and that `nginx` is running as user/group `www-data`.

In this setup, `uwsgi` running as a `systemd` service as `root` creates a unix socket with read-write access
to both `EtebaseUser` and `nginx`. It then drops its `root` privilege and runs `etebase` as `EtebaseUser`.

`nginx` listens on the `https` port (or a non standard port `https` port if desired), delivers static pages directly
and for everything else, communicates with `etebase` over the unix socket.
