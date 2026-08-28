"""The root URLconf."""

from django.urls import include, path

from adminsite import urls as adminsite_urls

urlpatterns = [
    path("admin/", include(adminsite_urls)),
]
