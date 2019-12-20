FROM python:3-alpine

RUN apk update && \
    apk add \
        python3 \
        python3-dev \
        build-base \
        linux-headers \
        pcre-dev && \
    rm -rf /var/cache/apk/*

RUN pip3 install \
        virtualenv \
        uwsgi

COPY ./ /var/etesync_server

WORKDIR /var/etesync_server

RUN virtualenv -p python3 .venv && \
    source .venv/bin/activate && \
    pip3 install -r ./requirements.txt

RUN mkdir -p /etc/uwsgi/sites

COPY ./example-configs/docker/etesync.ini /etc/uwsgi/sites/etesync.ini

RUN addgroup -S EtesyncGroup && adduser -S EtesyncUser -G EtesyncGroup

COPY ./example-configs/docker/entrypoint.sh /tmp/entrypoint.sh

ENTRYPOINT /bin/ash /tmp/entrypoint.sh
