"""One of the two modules `billing.urls` could mean.

Its own route is written here and is enumerated at the path this file gives it. What the
ambiguity costs is the PREFIX: this list is not mounted under `pay/`, because saying it
was would be saying that the other one is not, and nothing in the repository says either.
"""
from django.urls import path

from alpha.billing import views

urlpatterns = [
    path("charge/", views.charge),
]
