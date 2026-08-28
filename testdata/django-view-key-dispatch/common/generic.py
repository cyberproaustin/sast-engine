"""The generic verbs. A key resolves to a class, and the class answers through its base."""

import subprocess

from django.http import HttpResponse


class PublishView:
    model = None

    def post(self, request, page_id):
        # POSITIVE. Two indirections at once: the address comes from a string key and the
        # verb comes from a resolved base. Neither the URLconf nor `PagePublishView`
        # contains a line of this.
        target = request.POST["notify"]
        out = subprocess.check_output("mail -s published " + target, shell=True)
        return HttpResponse(out)


class ObjectListView:
    model = None

    def get(self, request):
        # NEGATIVE. The base's `index_view_class` is None and the page viewset overrides
        # it, so no route reaches this body. A resolver that read the property's class
        # attribute on the class that DECLARED the property rather than on the viewset
        # would report this at `/admin/pages/`.
        column = request.GET["order"]
        return HttpResponse(subprocess.check_output("sort -k" + column + " /srv/pages", shell=True))
