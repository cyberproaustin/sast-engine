"""The root URLconf. It mounts a PACKAGE, and the package holds no routes of its own."""
from django.urls import include, path

urlpatterns = [
    path("shop/", include("shop.urls")),
]
