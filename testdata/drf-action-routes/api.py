"""A router turns one viewset into six routes, and one more for every `@action`.

The six were enumerated and the extras were not, which is not a missing path but a
missing ENTRY POINT -- and an entry point is what anchors a flow to something a stranger
can reach. linkding's `/api/bookmarks/check/` takes a URL out of `request.GET` and fetches
it, and the engine's own surface report named `check` under "nothing in the program calls
them by name" while the flow behind it sat there, intact and unanchored.

`DefaultRouter` makes no distinction: it walks the class once and builds a route for each
standard action and for each dynamically routed method it finds on the way.
"""

import requests
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.routers import DefaultRouter


class BookmarkViewSet(viewsets.GenericViewSet):
    def list(self, request):
        # NEGATIVE. One of the standard six, and already enumerated before this corpus
        # existed. It fetches nothing.
        return Response({"bookmarks": []})

    @action(methods=["get"], detail=False)
    def check(self, request):
        # POSITIVE. A list action, served at `/bookmarks/check/`. The URL comes out of the
        # query string and reaches an outbound request with no destination check anywhere.
        url = request.GET.get("url")
        page = requests.get(url, timeout=10)
        return Response({"title": page.text})

    @action(methods=["post"], detail=True, url_path="re-fetch")
    def refetch(self, request, pk=None):
        # POSITIVE. A detail action under an explicit `url_path`, served at
        # `/bookmarks/<pk>/re-fetch/`. The decorator is the only place either fact is
        # written down.
        target = request.POST.get("target")
        page = requests.get(target, timeout=10)
        return Response({"title": page.text})

    @action(methods=["get"], detail=False)
    def status(self, request):
        # NEGATIVE. Routed exactly as the two above and reaching a destination the
        # program wrote itself. Being reachable is not being a weakness.
        page = requests.get("https://status.example.test/health", timeout=10)
        return Response({"status": page.text})


class UnregisteredViewSet(viewsets.GenericViewSet):
    @action(methods=["get"], detail=False)
    def probe(self, request):
        # NEGATIVE, and the near miss this corpus exists to hold. The decorator is
        # identical to the positive's and this class is never registered on a router, so
        # nothing routes it and there is no entry point to anchor the flow to. A rule
        # that read the decorator alone would report it.
        url = request.GET.get("url")
        page = requests.get(url, timeout=10)
        return Response({"title": page.text})


router = DefaultRouter()
router.register(r"bookmarks", BookmarkViewSet, basename="bookmark")
