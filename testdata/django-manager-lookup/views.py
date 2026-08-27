"""`Model.objects.get(pk=...)` — the shape a record-selector channel was written for,
measured against ten production repositories, and withdrawn.

Every view here is silent, and the corpus exists to keep it that way. It is the negative
half of a rule that was built and not shipped: `get` is Django's record selector and no
ownership rule could see one, so a channel matching `get` on a `.objects.` receiver was
written, measured, and withdrawn at 0 true findings out of 23 on the application surface
of five Django applications. Each view below records one of the reasons.

The near-misses at the bottom are the other half of the same measurement: `get` is
written 10050 times across the corpus's seven Python repositories and only 1675 of those
are on a manager, so a channel that matched the bare word would be wrong five times out
of six. Those must stay silent whatever else changes.
"""
import os

from django.core.cache import cache
from django.http import JsonResponse

from .models import ApiToken, Bookmark, Bundle


def _bundle_for(request, bundle_id):
    """The ownership check as applications actually write it.

    The predicate is IN the query -- there is no comparison to find and no guard to
    evaluate -- and it sits in a helper the handler hands its request to. That is the
    idiom: linkding writes six of these in one module. `actor-identity` is seeded from a
    property read on the ENTRY POINT's own parameter, so one frame down there is no
    identity anywhere and `owner=request.user`, written right here in the call, cannot be
    seen. Three of linkding's six new findings were this exact function shape, and the
    query that names the owner is why all three were false.
    """
    return Bundle.objects.get(pk=bundle_id, owner=request.user)


def bundle_detail(request, bundle_id):
    bundle = _bundle_for(request, bundle_id)
    return JsonResponse({"name": bundle.name})


def token_detail(request, token_id):
    """The same relation stated in the handler itself, where identity IS visible."""
    token = ApiToken.objects.get(id=token_id, user=request.user)
    return JsonResponse({"label": token.label})


def bookmark_detail(request, bookmark_id):
    """The positive the withdrawn channel was for: a caller's key, a manager, no owner.

    Nothing here relates the record to whoever asked, so this is the shape the rule would
    have reported -- and it is exactly the shape that could not be told apart from the
    twenty-three false ones. saleor's staff mutations look like this and are gated by a
    `Meta.permissions` declaration the engine does not read; archivebox's API looks like
    this and shares every row with every authenticated caller on purpose.
    """
    bookmark = Bookmark.objects.get(pk=bookmark_id)
    return JsonResponse({"url": bookmark.url})


def share_bookmark(request):
    """A key the SERVER made, which is not a key the caller chose.

    The bookmark is created from the caller's data and the row's primary key is then read
    back off it. Three of linkding's findings were this: the taint on the key is real and
    the caller never picked the record, which is the judgement the store model already
    records about a primary key an auto-increment column produced.
    """
    created = Bookmark(url=request.POST.get("url"))
    created.save()
    stored = Bookmark.objects.get(pk=created.id)
    return JsonResponse({"url": stored.url})


def search(request):
    """A filter is how a program SEARCHES, and a search takes the caller's word by design.

    `filter` and `exclude` were the obvious pair to add beside `get` -- 2963 calls across
    the corpus against 1675 -- and this is why they were not: the caller choosing which
    rows come back is the feature.
    """
    term = request.GET.get("q", "")
    rows = Bookmark.objects.filter(title__icontains=term)
    return JsonResponse({"count": len(rows)})


def preferences(request):
    """The near-misses. Every one of these is a `get` and none of them is a record.

    A dictionary the handler built, the process environment, and a cache keyed by
    whatever the caller asked for. A channel that matched the method name alone would
    have read all three as record selection.
    """
    defaults = {"theme": "dark", "density": "compact"}
    chosen = defaults.get(request.GET.get("pref", "theme"))
    region = os.environ.get("APP_REGION", "eu")
    cached = cache.get(request.GET.get("key", "summary"))
    return JsonResponse({"pref": chosen, "region": region, "cached": cached})
