"""Views nothing in this file registers and nothing in this file names a path for.

A view here is reached by a config class in another file, through an attribute that class
resolved from a string. Enumerate the config's routes or these bodies are unreachable --
and unreachable code is code excused from judgement.
"""
import subprocess

from django.db import connection
from django.http import HttpResponse
from django.views.generic import DetailView, ListView, TemplateView


class CatalogueIndexView(ListView):
    """NEGATIVE. Reading the query string is not a weakness; where it goes is."""

    model = None

    def get(self, request):
        return HttpResponse(request.GET.get("sort", "name"))


class ProductDetailView(DetailView):
    def get(self, request, product_slug, pk):
        # POSITIVE. Reached only through `CatalogueOnlyConfig.get_urls()`, whose view is
        # `self.detail_view` -- an attribute assigned in `ready()` from a class NAME.
        fmt = request.GET["format"]
        out = subprocess.check_output("convert product.png out." + fmt, shell=True)
        return HttpResponse(out)


class ReviewVoteView(TemplateView):
    def post(self, request, product_pk, pk):
        # POSITIVE. Three configs compose this address: the reviews app is mounted by the
        # catalogue app, which is mounted by the shop, which the root URLconf mounts at
        # the empty prefix. No file carries more than one link of that chain.
        delta = request.POST["delta"]
        with connection.cursor() as cur:
            cur.execute("UPDATE review SET votes = votes + %s WHERE id = %s" % (delta, pk))
        return HttpResponse("ok")


class ExportView(TemplateView):
    """NEGATIVE. A second class of this name lives in `dashboard/views.py`.

    The config resolves its view by NAME, so the name is the whole of the evidence, and
    here it names two classes. Binding the route to either is a claim that a request to
    `catalogue/export/` runs that function, and one of the two claims is false. A route
    the surface does not contain is a known gap; a route bound to the wrong handler is a
    wrong answer sent to a maintainer, so this resolves to nothing.
    """

    def get(self, request):
        name = request.GET["report"]
        out = subprocess.check_output("cat /var/exports/" + name, shell=True)
        return HttpResponse(out)
