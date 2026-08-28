"""Views that bind themselves to a model and never name a path.

The decorator writes a key. `dcim/urls.py` reads the same key. Neither file contains an
expression that names both an address and a handler.
"""
import subprocess

from django.http import HttpResponse

from core.views import generic
from utilities.views import register_model_view

from .models.sites import Device, Region


@register_model_view(Region, "list", path="", detail=False)
class RegionListView(generic.ObjectListView):
    """No body at all. Every verb it answers is in the base."""

    queryset = Region.objects.all()


@register_model_view(Region, "add", detail=False)
@register_model_view(Region, "edit")
class RegionEditView(generic.ObjectEditView):
    """Two registrations, one class: `add` on the list path and `edit` on the detail one."""

    queryset = Region.objects.all()


@register_model_view(Region, "sync")
class RegionSyncView(generic.ObjectEditView):
    def post(self, request, pk):
        # POSITIVE. A registered view that DOES write its own handler. Its own `post`
        # wins over the inherited one, which is the order Python resolves a method in.
        target = request.POST["target"]
        out = subprocess.check_output("rsync region-" + str(pk) + " " + target, shell=True)
        return HttpResponse(out)


@register_model_view(Region, "bulk_import", path="import", detail=False)
class RegionImportView(generic.ObjectEditView):
    """`path` overrides `name`: the address is `import/` and the route name is not."""

    queryset = Region.objects.all()


@register_model_view(Device, "edit")
class DeviceEditView(generic.ObjectEditView):
    """NEGATIVE. `Device` is a model in two applications of this program.

    The decorator names the class and the class alone, so which app label the registry
    filed this under is not readable -- and the URL builder asks by app label. Guessing one
    would put this view at an address in the wrong application, so it resolves to nothing.
    The handler below is a live command injection: a pass that claims this registration
    reports it, at an address that does not exist.
    """

    queryset = Device.objects.all()

    def post(self, request, pk):
        serial = request.POST["serial"]
        return HttpResponse(subprocess.check_output("provision " + serial, shell=True))
