"""NEGATIVE."""
from django.http import HttpResponse


def charge(request):
    return HttpResponse("ok")
