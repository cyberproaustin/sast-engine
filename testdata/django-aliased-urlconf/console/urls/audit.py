"""The second aliased module, so the mount is a table rather than a single case."""
from django.urls import path

from console import views

urlpatterns = [
    path("trail/", views.trail),
]
