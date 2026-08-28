"""Where the order views actually are."""
import subprocess

from django.http import HttpResponse
from django.views import View


class RefundView(View):
    def post(self, request, pk):
        # POSITIVE. Served at /shop/orders/<pk>/refund/, and the three files that decide
        # that path -- the root URLconf, the package that splices the lists, and the
        # submodule that writes the route -- none of them name this class's module.
        reason = request.POST["reason"]
        return HttpResponse(
            subprocess.check_output("shopctl refund --reason " + reason, shell=True))


def order_index(request):
    # NEGATIVE.
    return HttpResponse("[]")
