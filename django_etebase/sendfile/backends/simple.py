from email.utils import mktime_tz, parsedate_tz
import re

from django.core.files.base import File
from django.http import HttpResponse, HttpResponseNotModified
from django.utils.http import http_date


def sendfile(request, filepath, **kwargs):
    '''Use the SENDFILE_ROOT value composed with the path arrived as argument
    to build an absolute path with which resolve and return the file contents.

    If the path points to a file out of the root directory (should cover both
    situations with '..' and symlinks) then a 404 is raised.
    '''
    statobj = filepath.stat()

    # Respect the If-Modified-Since header.
    if not was_modified_since(request.META.get('HTTP_IF_MODIFIED_SINCE'),
                              statobj.st_mtime, statobj.st_size):
        return HttpResponseNotModified()

    with File(filepath.open('rb')) as f:
        response = HttpResponse(f.chunks())

    response["Last-Modified"] = http_date(statobj.st_mtime)
    return response


def was_modified_since(header=None, mtime=0, size=0):
    """
    Was something modified since the user last downloaded it?

    header
      This is the value of the If-Modified-Since header.  If this is None,
      I'll just return True.

    mtime
      This is the modification time of the item we're talking about.

    size
      This is the size of the item we're talking about.
    """
    try:
        if header is None:
            raise ValueError
        matches = re.match(r"^([^;]+)(; length=([0-9]+))?$", header,
                           re.IGNORECASE)
        header_date = parsedate_tz(matches.group(1))
        if header_date is None:
            raise ValueError
        header_mtime = mktime_tz(header_date)
        header_len = matches.group(3)
        if header_len and int(header_len) != size:
            raise ValueError
        if mtime > header_mtime:
            raise ValueError
    except (AttributeError, ValueError, OverflowError):
        return True
    return False
