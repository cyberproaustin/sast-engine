"""The generic views every registered subclass inherits its verbs from.

1,113 of netbox's 1,141 decorator registrations decorate a class with NO request handling
in it: the subclass carries the queryset and the form and the base carries `get` and
`post`. A lookup that stops at the class the decorator names reaches an empty class for all
but 28 of them, so the base has to be resolved -- and resolved to a base this PROGRAM
defines, because a base matched on its bare name finds whichever unrelated class shares it.
"""
import subprocess

from django.db import connection
from django.http import HttpResponse


class ObjectEditView:
    queryset = None
    form = None

    def get(self, request, pk):
        # NEGATIVE. The edit form. Reads the record and renders it.
        return HttpResponse(str(pk))

    def post(self, request, pk):
        # POSITIVE. Every `edit` route in the program runs THIS body, and the only place
        # any of those addresses is written is a `get_model_urls` call that names a key.
        ordering = request.POST["_order"]
        with connection.cursor() as cur:
            cur.execute("UPDATE dcim_region SET pos = %s WHERE id = %s" % (ordering, pk))
        return HttpResponse("ok")


class ObjectListView:
    queryset = None
    table = None

    def get(self, request):
        # POSITIVE. The list route of every registered model, reached the same way.
        column = request.GET["sort"]
        out = subprocess.check_output("sort -k " + column + " /var/cache/objects", shell=True)
        return HttpResponse(out)
