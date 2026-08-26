"""An included URLconf.

Every route here is served under the prefix the ROOT file gives it, and this file carries
no trace of that prefix. That is why the composition is a program-wide pass and not
something a module can work out on its own.
"""
from django.urls import path, re_path

from api import views

urlpatterns = [
    path("checks/", views.checks),
    path("checks/<uuid:code>/flips/", views.flips),
    # A named group is a parameter written for the older registrar. The rest of the
    # pattern is left exactly as it was written.
    re_path(r"^ping/(?P<code>[\w-]+)/(?P<n>\d+)$", views.ping),
]
