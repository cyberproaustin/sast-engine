"""Handlers of the aliased URLconfs."""
import subprocess

from django.http import HttpResponse


def locked(request):
    # POSITIVE. Served at /console/reports/locked/, two aliased mounts away from the file
    # that writes the route.
    since = request.GET["since"]
    return HttpResponse(subprocess.check_output("conctl locked --since " + since, shell=True))


def locked_results(request):
    # NEGATIVE.
    return HttpResponse("[]")


def trail(request):
    # NEGATIVE.
    return HttpResponse("[]")
