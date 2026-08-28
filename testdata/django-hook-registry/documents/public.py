"""The public download. NEGATIVE: it reads a primary key and no caller-supplied text."""

from django.http import HttpResponse


def serve(request, pk):
    return HttpResponse("document %d" % pk)
