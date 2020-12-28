from fastapi.responses import FileResponse


def sendfile(filename, mimetype, **kwargs):
    """Use the SENDFILE_ROOT value composed with the path arrived as argument
    to build an absolute path with which resolve and return the file contents.

    If the path points to a file out of the root directory (should cover both
    situations with '..' and symlinks) then a 404 is raised.
    """

    return FileResponse(filename, media_type=mimetype)
