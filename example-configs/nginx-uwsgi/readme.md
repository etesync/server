# Running `etesync` under `nginx` and `uwsgi`

This configuration assumes that etesync server has been installed in the home folder of a non privileged user 
called `EtesyncUser` following the instructions in <https://github.com/etesync/server-skeleton>. Also that static 
files have been collected at `/srv/http/etesync_server` by running the following commands:

    sudo mkdir -p /srv/http/etesync_server/static
    sudo chown -R EtesyncUser /srv/http/etesync_server
    sudo su EtesyncUser
    cd /path/to/etesync
    ln -s /srv/http/etesync_server/static static
    ./manage.py collectstatic

It is also assumed that `nginx` and `uwsgi` have been installed system wide by `root`, and that `nginx` is running as user/group `www-data`. 

In this setup, `uwsgi` running as a `systemd` service as `root` creates a unix socket with read-write access 
to both `EtesyncUser` and `nginx`. It then drops its `root` privilege and runs `etesync` as `EtesyncUser`.

`nginx` listens on the `https` port (or a non standard port `https` port if desired), delivers static pages directly 
and for everything else, communicates with `etesync` over the unix socket.
