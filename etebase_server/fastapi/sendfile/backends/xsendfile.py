from fastapi import Response


def sendfile(filename, **kwargs):
    filename = str(filename)
    return Response(headers={"X-Sendfile": filename})
