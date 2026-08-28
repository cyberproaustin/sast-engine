"""The dashboard half of the program, and the second class the ambiguity is made of."""
import subprocess

from django.http import HttpResponse
from django.views.generic import TemplateView


class RangeReorderView(TemplateView):
    def post(self, request, pk):
        # POSITIVE. The registration wraps this class in `login_required(...)`, so the
        # view sits one call deep inside the argument of another call. A reader that
        # matches only `X.as_view()` in the argument position finds nothing here.
        order = request.POST["order"]
        out = subprocess.check_output("reorder-range " + str(pk) + " " + order, shell=True)
        return HttpResponse(out)


class ExportView(TemplateView):
    """NEGATIVE. The other half of the name collision. See `catalogue/views.py`."""

    def get(self, request):
        name = request.GET["report"]
        out = subprocess.check_output("cat /var/dashboard/" + name, shell=True)
        return HttpResponse(out)
