"""The class the key `edit` resolves to."""

from django.db import connection
from django.http import HttpResponse


class PageEditView:
    def post(self, request, page_id):
        # POSITIVE. `/admin/pages/<int:page_id>/edit/` runs this body, and the only place
        # that address is written is a `path()` whose view argument is a string key.
        slug = request.POST["slug"]
        with connection.cursor() as cur:
            cur.execute("UPDATE pages SET slug = '%s' WHERE id = %s" % (slug, page_id))
        return HttpResponse("ok")
