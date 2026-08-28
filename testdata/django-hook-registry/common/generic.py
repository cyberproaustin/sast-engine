"""The generic views the applications inherit their verbs from.

31 of wagtail's 220 registrations name a class that declares a queryset and two columns
and no request handling at all: `class IndexView(generic.IndexView)` answers every GET
through this layer. A lookup that stops at the class the URLconf names reaches a class
with no verb in it, so five of `wagtail/contrib/redirects/urls.py`'s seven routes were
enumerated as nothing.

The base has to be resolved to a base this PROGRAM defines. Eleven other classes in
wagtail are also called `EditView`, so a base matched on its bare name binds a route to
whichever one the walk reached first.
"""

import subprocess

from django.db import connection
from django.http import HttpResponse


class EditView:
    model = None

    def post(self, request, pk):
        # POSITIVE. The edit route of the documents admin runs THIS body. The subclass
        # that the URLconf names declares a model and nothing else.
        label = request.POST["label"]
        with connection.cursor() as cur:
            cur.execute("UPDATE docs SET label = '%s' WHERE id = %s" % (label, pk))
        return HttpResponse("ok")


class IndexView:
    model = None

    def get(self, request):
        # POSITIVE. The listing route, reached the same way and at the address the hook
        # supplies rather than at the one the declaring module would have given it.
        order = request.GET["sort"]
        out = subprocess.check_output("ls -" + order + " /srv/docs", shell=True)
        return HttpResponse(out)
