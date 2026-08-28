"""NEGATIVE. The report view reads no caller-supplied text and reports nothing."""

from django.http import HttpResponse


class LockedView:
    def get(self, request):
        return HttpResponse("locked pages")
