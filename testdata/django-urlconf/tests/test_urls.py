"""NEGATIVE. A test's URLconf is not the application's attack surface.

`override_settings(ROOT_URLCONF=...)` is how a Django test mounts a handler of its own,
and a route that exists only in a test does not exist in the program that is deployed.
"""
from django.urls import path

from front import views

urlpatterns = [
    path("test-only/", views.check_log),
]
