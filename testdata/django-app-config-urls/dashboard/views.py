"""The dashboard half of the program, and the second class the ambiguity is made of."""
import subprocess

from django.http import HttpResponse
from django.views.generic import FormView, TemplateView


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


class RangeUploadView(FormView):
    """Django's own FormView answers POST and calls this; the subclass writes no `post`.

    A config-registered view of this shape was ONE entry point, at ANY, on whichever hook
    the list reached first -- usually `get_context_data`, which only reads -- so the body
    that acts on the request was outside the route entirely. 28 of oscar's registrations
    are written this way. It is now two: a GET on the context and a POST on `form_valid`.

    NEITHER HALF CARRIES A FINDING, and that is a fact about the engine rather than about
    this class. A Django class-based view reaches the request through `self.request`, a
    property of the view instance, and the taint model sources a handler's `request`
    PARAMETER and route captures and not that -- so a hook-shaped handler has no caller
    data in it however it is reached. What the two entry points buy today is a surface with
    the right verbs at the right address; what they will buy is every one of these bodies,
    the moment `self.request` is a source. The corpus asserts the enumeration and claims no
    finding, which is the honest half of it.
    """

    form_class = None

    def get_context_data(self, **kwargs):
        # The GET half, at GET rather than at ANY.
        ctx = super().get_context_data(**kwargs)
        ctx["filter"] = self.request.GET.get("filter", "")
        return ctx

    def form_valid(self, form):
        # The POST half, reached through Django's own `post` and never through a method
        # this class names. Before, this body was not on the surface at all.
        target = self.request.POST["destination"]
        subprocess.check_output("cp /tmp/upload " + target, shell=True)
        return HttpResponse("ok")
