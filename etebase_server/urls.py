from django.conf import settings
from django.conf.urls import include, url
from django.contrib import admin
from django.urls import path
from django.views.generic import TemplateView

urlpatterns = [
    url(r"^api/", include("django_etebase.urls")),
    url(r"^admin/", admin.site.urls),
    path("", TemplateView.as_view(template_name="success.html")),
]

if settings.DEBUG:
    urlpatterns += [
        url(r"^api-auth/", include("rest_framework.urls", namespace="rest_framework")),
    ]
