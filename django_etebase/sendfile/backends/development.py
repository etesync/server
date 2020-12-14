import os.path

from django.views.static import serve


def sendfile(request, filename, **kwargs):
    """
    Send file using Django dev static file server.

    .. warning::

        Do not use in production. This is only to be used when developing and
        is provided for convenience only
    """
    dirname = os.path.dirname(filename)
    basename = os.path.basename(filename)
    return serve(request, basename, dirname)
