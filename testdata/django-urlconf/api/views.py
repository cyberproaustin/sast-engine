"""Handlers of the URLconf that is mounted from somewhere else."""
import subprocess

from django.http import HttpResponse


def checks(request):
    # NEGATIVE.
    return HttpResponse("[]")


def flips(request, code):
    # POSITIVE. Served at /api/v3/checks/<code>/flips/, and the prefix is written in a
    # file this one does not import and cannot see.
    since = request.GET["since"]
    return HttpResponse(subprocess.check_output("hcctl flips --since " + since, shell=True))


def ping(request, code, n):
    # NEGATIVE.
    return HttpResponse(code)
