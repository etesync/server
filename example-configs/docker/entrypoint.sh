#!/bin/ash
source ./.venv/bin/activate
python3 ./manage.py makemigrations --noinput
python3 ./manage.py migrate --noinput
python3 ./manage.py collectstatic --noinput
uwsgi --enable-threads --emperor /etc/uwsgi/sites