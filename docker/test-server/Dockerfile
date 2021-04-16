FROM python:3.9.0-alpine

ARG ETESYNC_VERSION

ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PIP_NO_CACHE_DIR=1

# install packages and pip requirements first, in a single step,
COPY /requirements.txt /requirements.txt
RUN set -ex ;\
    apk add libpq postgresql-dev --virtual .build-deps coreutils gcc libc-dev libffi-dev make ;\
    pip install -U pip ;\
    pip install --no-cache-dir --progress-bar off -r /requirements.txt ;\
    apk del .build-deps make gcc coreutils ;\
    rm -rf /root/.cache

COPY . /app

RUN set -ex ;\
    mkdir -p /data/static /data/media ;\
    cd /app ;\
    mkdir -p /etc/etebase-server ;\
    cp docker/test-server/etebase-server.ini /etc/etebase-server ;\
    sed -e '/ETEBASE_CREATE_USER_FUNC/ s/^#*/#/' -i /app/etebase_server/settings.py ;\
    chmod +x docker/test-server/entrypoint.sh

# this is a test image and should start up quickly, so it starts with the DB
# and static data already fully set up.
RUN set -ex ;\
    cd /app ;\
    python manage.py migrate ;\
    python manage.py collectstatic --noinput

ENV ETESYNC_VERSION=${ETESYNC_VERSION}
VOLUME /data
EXPOSE 3735

ENTRYPOINT ["/app/docker/test-server/entrypoint.sh"]
