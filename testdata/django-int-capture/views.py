from django.db import connection
from django.http import HttpResponse

from store import notes


def note_delete(request, pk):
    # POSITIVE. `<int:pk>` is the caller choosing which record is removed, and an IDOR is
    # precisely the caller sending a different integer. The converter constrains what the
    # value can HOLD and says nothing about which row it names.
    notes.delete(pk)
    return HttpResponse("ok")


def note_delete_owned(request, pk):
    # NEGATIVE. The same route and the same converter, with the caller's identity in the
    # operation. Selecting inside the caller's own rows cannot reach anybody else's,
    # which is how multi-tenant code is normally written.
    notes.delete_for_owner(pk, request.user.id)
    return HttpResponse("ok")


def note_sql(request, pk):
    # NEGATIVE, and the one that must stay silent for the ORIGINAL reason: `[0-9]+` holds
    # no quote and no semicolon, so the value cannot break out of the statement. Nothing
    # about the fix relaxes that.
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT title FROM note WHERE id = {pk}")
        return HttpResponse(str(cursor.fetchall()))


def note_sql_slug(request, slug):
    # POSITIVE, and the control that proves the converter is what does the work above.
    # Django's `str` converter is `[^/]+`, which carries a quote perfectly well.
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT title FROM note WHERE slug = '{slug}'")
        return HttpResponse(str(cursor.fetchall()))
