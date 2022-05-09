import os

from django.conf import settings
from django.contrib import admin
from django.urls import path
from django.views.generic import TemplateView
from django.views.static import serve
from django.contrib.staticfiles import finders

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", TemplateView.as_view(template_name="success.html")),
]
