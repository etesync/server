from __future__ import absolute_import

from fastapi import Response

from ..utils import _convert_file_to_url


def sendfile(filename, **kwargs):
    return Response(headers={"X-Accel-Redirect": _convert_file_to_url(filename)})
