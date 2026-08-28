"""NEGATIVE. Two classes no route in this program reaches.

`PageEditView` shares its name with the class the page viewset holds. It carries a live
command injection so that a resolver matching the bare name fails loudly: the finding
would be reported at `/admin/pages/<int:page_id>/edit/`, an address that runs the other
class entirely.
"""

import subprocess

from django.http import HttpResponse


class PageEditView:
    def post(self, request, pk):
        target = request.POST["archive"]
        return HttpResponse(subprocess.check_output("tar cf " + target, shell=True))


class SnippetHistoryView:
    def get(self, request, pk):
        return HttpResponse("history of %d" % pk)
