# Running `etesync` under `nginx` and `uwsgi`

This configuration assumes that etesync server has been installed in the home folder of a non privileged user 
called `EtesyncUser` following the instructions in <https://github.com/etesync/server-skeleton>. Also that static 
files have been collected by running the following command from within the `etesync` folder.

    ./manage.py collectstatic

Before the above command, it might be necessary to add the line 

    STATIC_ROOT = os.path.join(BASE_DIR, 'static/')
    
in `etesync_server/settings.py` below the line `STATIC_URL = '/static/'`    

It is also assumed that `nginx` and `uwsgi` have been installed system wide by `root` or a `sudo` user.

In this setup, `uwsgi` running as a `systemd` service as `root` creates a unix socket with read-write access 
to both `EtesyncUser` and `nginx`. It then drops its `root` privilege and runs `etesync` as `EtesyncUser`.

`nginx` listens on the `https` port (or a non standard port `https` port if desired). `nginx` delivers static pages directly 
and for everything else, communicates with `etesync` over the unix socket.
