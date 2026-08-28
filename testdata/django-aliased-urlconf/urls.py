"""The root URLconf, mounting a MODULE it imported under a name of its own."""
from django.urls import include, path

from console import urls as console_urls

urlpatterns = [
    path("console/", include(console_urls)),
]
