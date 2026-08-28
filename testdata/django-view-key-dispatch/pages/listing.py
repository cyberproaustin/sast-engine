"""The class the key `index` resolves to, through a property declared on the base."""

import subprocess

from django.http import HttpResponse


class PageIndexView:
    def get(self, request):
        # POSITIVE. `/admin/pages/`. The property that builds this view is on
        # `BaseViewSet` and reads `self.index_view_class`, which `PageViewSet` overrides
        # -- so the attribute is resolved on the viewset and not on the class that wrote
        # the property, which is the answer Python gives.
        query = request.GET["q"]
        return HttpResponse(subprocess.check_output("grep -r " + query + " /srv/pages", shell=True))
