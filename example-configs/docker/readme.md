# Running `etesync` under `nginx` and `uwsgi` using `docker`
- rename [etesync-server.ini.example](../../etesync-server.ini.example) to `etesync-server.ini` and add your allowed hosts
- adjust the `server_name` option in [etesync.nginx.conf](./etesync.nginx.conf)
- create a `secret.txt` file 
```bash
cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1 > secret.txt
```
- run `docker-compose up -d`