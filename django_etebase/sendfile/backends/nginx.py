from __future__ import absolute_import

from django.http import HttpResponse

from ..utils import _convert_file_to_url


def sendfile(request, filename, **kwargs):
    response = HttpResponse()
    response['X-Accel-Redirect'] = _convert_file_to_url(filename)

    return response
