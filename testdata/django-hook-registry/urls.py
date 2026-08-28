"""The root URLconf: the only file that says where the admin is served."""

from django.urls import include, path

from adminsite import urls as adminsite_urls
from documents import urls as docs_urls

urlpatterns = [
    path("admin/", include(adminsite_urls)),
    path("documents/", include(docs_urls)),
]
