import os

from django.conf import settings
from django.conf.urls import include, url
from django.contrib import admin
from django.urls import path, re_path
from django.views.generic import TemplateView
from django.views.static import serve
from django.contrib.staticfiles import finders

urlpatterns = [
    url(r"^api/", include("django_etebase.urls")),
    url(r"^admin/", admin.site.urls),
    path("", TemplateView.as_view(template_name="success.html")),
]

if settings.DEBUG:
    urlpatterns += [
        url(r"^api-auth/", include("rest_framework.urls", namespace="rest_framework")),
    ]

    def serve_static(request, path):
        filename = finders.find(path)
        dirname = os.path.dirname(filename)
        basename = os.path.basename(filename)

        return serve(request, basename, dirname)

    urlpatterns += [re_path(r"^static/(?P<path>.*)$", serve_static)]
