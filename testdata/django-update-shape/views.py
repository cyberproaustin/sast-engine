"""Python's two `update` calling conventions, and the uncertainty between them.

A mapping merge takes another mapping as a positional argument. A Django queryset update
takes the fields it will write as keywords; the rows were already selected by the
queryset it is called on. Those are structural facts in the call, independent of what a
variable happens to be named.

An untyped positional call proves neither one. It remains reported at reduced confidence:
silence requires positive evidence that the argument is one of Python's own containers.
"""
from django.http import JsonResponse
from django.db.models import QuerySet

from .models import Widget


def merge_payload(request):
    payload = payload_function(request.POST)
    payload.update({"extra_payload": request.POST["extra"]})

    params: dict[str, str] = request.POST
    payload.update(params)
    return JsonResponse(payload)


def update_widget(request):
    chosen = request.POST["id"]
    records: QuerySet[Widget] = Widget.objects.filter(pk=chosen)
    records.update(label=chosen)
    return JsonResponse({"ok": True})


def update_unknown(request):
    store = get_store()
    store.update(request.POST)
    return JsonResponse({"ok": True})


def whoami(request):
    return JsonResponse({"id": request.user.id})


def payload_function(data):
    return {"data": data}


def get_store():
    return None
