from django.http import HttpResponse


def sendfile(request, filename, **kwargs):
    filename = str(filename)
    response = HttpResponse()
    response['X-Sendfile'] = filename

    return response
