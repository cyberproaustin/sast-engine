"""NEGATIVE. A route that exists at a path this corpus can state."""
from django.http import HttpResponse


def charge(request):
    return HttpResponse("ok")
