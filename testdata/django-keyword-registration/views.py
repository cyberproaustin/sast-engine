import subprocess

from django.http import HttpResponse
from django.views import View


def plain_view(request):
    # Reached only if the keyword-written registration is enumerated at all.
    name = request.GET["name"]
    out = subprocess.check_output("grep " + name + " /var/log/app.log", shell=True)
    return HttpResponse(out)


class ExampleList(View):
    def get(self, request):
        return HttpResponse("list")

    def post(self, request):
        label = request.POST["label"]
        out = subprocess.check_output("tag " + label + " /srv/data", shell=True)
        return HttpResponse(out)


class ExampleDetail(View):
    def get(self, request):
        # No caller data reaches anything here. The route is real and silent.
        return HttpResponse("detail")
