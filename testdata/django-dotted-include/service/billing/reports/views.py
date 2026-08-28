"""Handlers of a URLconf mounted from a file that names them only as a string."""
import subprocess

from django.http import HttpResponse


def export(request, pk):
    # POSITIVE. Served at /api/v2/export/<pk>/, and this file names neither the prefix
    # nor the module that supplies it.
    fmt = request.GET["format"]
    return HttpResponse(subprocess.check_output("billctl export --as " + fmt, shell=True))


def summary(request):
    # NEGATIVE. Nothing the caller supplies reaches anything.
    return HttpResponse("ok")
