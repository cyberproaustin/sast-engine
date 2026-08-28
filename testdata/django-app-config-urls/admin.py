"""NEGATIVE. `get_urls()` is not an app config's method alone.

Django's own `ModelAdmin` declares one, a DRF router declares one, and both return a list
of `path()` calls exactly as an app config does. What separates them is that an admin's
routes are mounted by machinery that writes no LABEL anywhere: the address they are served
at is composed from a model's app label and its name at run time, and nothing in this file
or any other says what it is.

So this class declares a route this pass can read and an address it cannot, and a route
whose address is not readable is not put on the surface. The handler below is written with
a live command injection on purpose: if the pass ever claims this registration, the claim
shows up as a finding at an address the application does not serve.
"""
import subprocess

from django.contrib import admin
from django.http import HttpResponse
from django.urls import path


class ProductAdmin(admin.ModelAdmin):
    def get_urls(self):
        return [
            path("lookup/", self.admin_site.admin_view(self.lookup)),
        ] + super().get_urls()

    def lookup(self, request):
        term = request.GET["term"]
        return HttpResponse(subprocess.check_output("lookup " + term, shell=True))
