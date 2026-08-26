"""The handlers a URLconf reaches, holding no evidence at all of how they are reached.

A Django view has no decorator and no path in it. The file that registers it is the only
place either exists, so a handler here is either enumerated from the URLconf or it is not
in the surface -- and everything it does is unreachable either way.
"""
import subprocess

from django.db import connection
from django.http import HttpResponse
from django.views import View
from rest_framework import viewsets

from front.models import Check


def index(request):
    # NEGATIVE. Reading the query string is not a weakness; where it goes is.
    return HttpResponse(request.GET.get("sort", "name"))


def check_log(request, code):
    # POSITIVE. Reached only through `detail_urls`, a list this file never mentions,
    # mounted under a prefix in the URLconf.
    tail = request.GET["tail"]
    out = subprocess.check_output("tail -n " + tail + " /var/log/checks.log", shell=True)
    return HttpResponse(out)


def check_ping(request, code, n):
    # NEGATIVE. A route capture is caller-supplied and this one goes nowhere.
    return HttpResponse(str(n))


def badge(request, slug):
    # NEGATIVE. Registered through a regex whose named group is the parameter.
    return HttpResponse(slug)


class CheckEdit(View):
    """Django dispatches a class-based view by verb: `get` answers GET, `post` answers
    POST, and one `as_view()` in the URLconf stands for both."""

    def get(self, request, code):
        # NEGATIVE. The same class, the verb that only reads.
        return HttpResponse(code)

    def post(self, request, code):
        # POSITIVE. The request is the SECOND parameter here, because a class-based view
        # answers in a method and `self` is the first.
        name = request.POST["name"]
        with connection.cursor() as cur:
            cur.execute("UPDATE checks SET name = '%s' WHERE code = '%s'" % (name, code))
        return HttpResponse("ok")


class CheckViewSet(viewsets.ModelViewSet):
    """A viewset is registered by CLASS on a router, which expands it into the standard
    six routes. Nothing in the class says where any of them are."""

    def get_queryset(self):
        # The hook a viewset overrides to scope its records, and where the four routes
        # this class names no method for land: a request for any of them reaches here.
        return Check.objects.filter(owner=self.request.user)

    def list(self, request):
        # NEGATIVE.
        return HttpResponse("[]")

    def create(self, request):
        # POSITIVE. GET and POST on the list path, GET, PUT, PATCH and DELETE on the
        # detail path, and every one of them is written as the single word `register`.
        with connection.cursor() as cur:
            cur.execute("INSERT INTO checks (name) VALUES ('" + request.POST["name"] + "')")
        return HttpResponse("ok")
