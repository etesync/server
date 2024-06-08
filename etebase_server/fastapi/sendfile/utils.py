import logging
from functools import lru_cache
from importlib import import_module
from pathlib import Path, PurePath
from urllib.parse import quote

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from fastapi import status

from ..exceptions import HttpError

logger = logging.getLogger(__name__)


@lru_cache(maxsize=None)
def _get_sendfile():
    backend = getattr(settings, "SENDFILE_BACKEND", None)
    if not backend:
        raise ImproperlyConfigured("You must specify a value for SENDFILE_BACKEND")
    module = import_module(backend)
    return module.sendfile


def _convert_file_to_url(path):
    try:
        url_root = PurePath(getattr(settings, "SENDFILE_URL", None))
    except TypeError:
        return path

    path_root = PurePath(settings.SENDFILE_ROOT)
    path_obj = PurePath(path)

    relpath = path_obj.relative_to(path_root)
    # Python 3.5: Path.resolve() has no `strict` kwarg, so use pathmod from an
    # already instantiated Path object
    url = relpath._flavour.pathmod.normpath(str(url_root / relpath))

    return quote(str(url))


def _sanitize_path(filepath):
    try:
        path_root = Path(getattr(settings, "SENDFILE_ROOT", None))
    except TypeError:
        raise ImproperlyConfigured("You must specify a value for SENDFILE_ROOT")

    filepath_obj = Path(filepath)

    # get absolute path
    # Python 3.5: Path.resolve() has no `strict` kwarg, so use pathmod from an
    # already instantiated Path object
    filepath_abs = Path(filepath_obj._flavour.pathmod.normpath(str(path_root / filepath_obj)))

    # if filepath_abs is not relative to path_root, relative_to throws an error
    try:
        filepath_abs.relative_to(path_root)
    except ValueError:
        raise HttpError(
            "generic", "{} wrt {} is impossible".format(filepath_abs, path_root), status_code=status.HTTP_404_NOT_FOUND
        )

    return filepath_abs


def sendfile(filename, mimetype="application/octet-stream", encoding=None):
    """
    Create a response to send file using backend configured in ``SENDFILE_BACKEND``

    ``filename`` is the absolute path to the file to send.
    """
    filepath_obj = _sanitize_path(filename)
    logger.debug(
        "filename '%s' requested \"\
        \"-> filepath '%s' obtained",
        filename,
        filepath_obj,
    )
    _sendfile = _get_sendfile()

    if not filepath_obj.exists():
        raise HttpError("does_not_exist", '"%s" does not exist' % filepath_obj, status_code=status.HTTP_404_NOT_FOUND)

    response = _sendfile(filepath_obj, mimetype=mimetype)

    response.headers["Content-Type"] = mimetype

    return response
