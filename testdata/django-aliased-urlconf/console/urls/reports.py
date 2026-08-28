"""Two levels below the root, and this file names neither prefix."""
from django.urls import path

from console import views

urlpatterns = [
    path("locked/", views.locked),
    path("locked/results/", views.locked_results),
]
