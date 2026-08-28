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

    Neither half carried a finding while `self.request` was not a source: a Django
    class-based view reaches the request through a property of the view INSTANCE, the model
    sourced a handler's `request` PARAMETER and its route captures, and so a hook-shaped
    handler had the right address, the right verb and no caller data in it. `form_valid` is
    the POSITIVE that closes that, and it is the same command injection any of the
    parameter-shaped views above would be reported for. The GET half stays silent for a
    reason that has nothing to do with the source: it reads `self.request.GET` into a
    template context, and a context is not an interpreter.
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
