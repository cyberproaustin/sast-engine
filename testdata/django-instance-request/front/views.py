"""A Django class-based view reads its input from `self.request`, and nothing hands it in.

Django's generic views are dispatched by the framework. `View.dispatch` assigns the
request to the INSTANCE and only then calls the method that answers, so the method a
subclass actually writes takes no request at all: `get_queryset(self)`,
`get_context_data(self, **kwargs)`, `form_valid(self, form)`. The caller's data is
`self.request.GET` and `self.request.POST`, one hop off the receiver.

Measured on django-oscar: 97 of its 177 routes anchor to one of those three hooks. Route
enumeration had already put every one of them on the surface at the right address with the
right verb, and the findings did not move at all -- 6 before, 6 after -- because a source
model that reads an entry point's PARAMETERS finds nothing in a method that has none.

What decides it is the ROUTE. `self.request` on a class no URLconf registers is not caller
data, and `self.request` on something that is not a view at all is not even a request:
Celery's bound tasks read `self.request.retries` and `self.request.is_eager` off a task
context, and plane holds five of them.
"""
import subprocess

from django.db import connection
from django.http import HttpResponse
from django.views.generic import DetailView, FormView, ListView


class OrderSearchView(ListView):
    """POSITIVE. `get_queryset` takes `self` and nothing else."""

    def get_queryset(self):
        # POSITIVE. The query string, reached through the instance, run by a shell. There
        # is no parameter here for any of the older rules to name.
        code = self.request.GET["code"]
        return subprocess.check_output("grep " + code + " /var/orders.log", shell=True)


class OrderUploadView(FormView):
    """POSITIVE. Django's own `post` runs the form and calls `form_valid`."""

    form_class = None

    def get_context_data(self, **kwargs):
        # NEGATIVE. The same source, and a template context is not an interpreter.
        ctx = super().get_context_data(**kwargs)
        ctx["filter"] = self.request.GET.get("filter", "")
        return ctx

    def form_valid(self, form):
        # POSITIVE. `form` is the only parameter and it is not the request.
        target = self.request.POST["destination"]
        with connection.cursor() as cur:
            cur.execute("INSERT INTO uploads (path) VALUES ('" + target + "')")
        return HttpResponse("ok")


class OrderDetailView(DetailView):
    """Which field, and which method. Both halves of the rule, on one routed class."""

    def get_queryset(self):
        # NEGATIVE. `self.request.user` is who Django AUTHENTICATED, not what the caller
        # sent, and it is the single most common thing read off `self.request` in every
        # repository measured -- oscar 90, wagtail 308, plane 130. Seeding the request
        # OBJECT rather than the fields of it that carry caller data would classify every
        # one of those as untrusted input.
        return subprocess.check_output("orders --for " + self.request.user.username,
                                       shell=True)

    def get_breadcrumbs(self):
        # POSITIVE, and the reason the unit is the CLASS rather than the method a route
        # names. Nothing routes to `get_breadcrumbs` and nothing in this program calls it:
        # Django's own template machinery does, while serving the request that reached
        # `get_queryset`. On django-oscar this is where the caller's data actually lives --
        # 38 of its 58 reads of a request field off `self.request` are in a method of a
        # routed class that is not the method the route names, and only 5 are in the
        # method it does.
        return subprocess.check_output("git log " + self.request.GET["ref"], shell=True)


class UnroutedSearchView(ListView):
    """NEGATIVE. Byte for byte the body of `OrderSearchView`, and no URLconf names it.

    A class nobody routes to is never dispatched, so its `self` is never a view holding a
    request. This is the whole precondition: the source is not "a method called
    get_queryset", it is "a method of a class a route reaches".
    """

    def get_queryset(self):
        code = self.request.GET["code"]
        return subprocess.check_output("grep " + code + " /var/orders.log", shell=True)


class ReportJob:
    """NEGATIVE. Not a view, and its `request` is not an HTTP request.

    A bound Celery task is written exactly like this and reads `self.request.retries`. A
    plain class carrying an attribute called `request` is not a shape a source rule may
    read; what makes the two classes above different is the registration, not the word.
    """

    def __init__(self, request):
        self.request = request

    def run(self):
        return subprocess.check_output("report " + self.request.GET["range"], shell=True)
