"""A literal `/` in front of caller data anchors a host, until something re-parses it.

`urljoin` resolves its second argument as a URL REFERENCE, and RFC 3986 says a reference
beginning `//` is a network-path reference whose authority REPLACES the base's. So
`urljoin("http://127.0.0.1:4096", "/" + path)` with `path = "/evil.example/x"` is
`http://evil.example/x`, and the prefix the application wrote bought nothing.

Ordinary concatenation is the contrast and it is why the whole-value rule exists: the
same `origin + "/" + path` handed straight to a client keeps the host in the literal, and
the caller is left with a path segment.

The proxy shape also needs the CALL to be described. A handler that forwards whatever
method arrived cannot call `get`, so it writes `requests.request(method, url)` -- and the
destination is the second argument, behind the verb.
"""

import requests
from urllib.parse import urljoin
from django.http import HttpResponse
from django.urls import re_path

ORIGIN = "http://127.0.0.1:4096"


def _proxy_url(path):
    rel = "/" if not path else f"/{path}"
    return urljoin(ORIGIN, rel)


def proxy(request):
    # POSITIVE. archivebox's `/opencode/<path>` line for line. The value is composed
    # behind a literal `/`, joined onto a configured origin, and forwarded under the
    # method the caller sent -- so the destination is argument 1.
    path = request.GET.get("path")
    upstream = requests.request("GET", _proxy_url(path), stream=True)
    return HttpResponse(upstream.content)


def joined_whole(request):
    # POSITIVE. The same resolver with nothing written in front at all.
    path = request.GET.get("path")
    upstream = requests.request("GET", urljoin(ORIGIN, path), stream=True)
    return HttpResponse(upstream.content)


def concatenated(request):
    # NEGATIVE, and the near miss this corpus exists to hold. The identical composition,
    # handed to a client instead of to a resolver: nothing re-parses it, the host stays
    # in the literal, and the caller has a path segment. A rule that read the `/` prefix
    # as dangerous would report this one too.
    path = request.GET.get("path")
    upstream = requests.get(ORIGIN + "/" + path, timeout=10)
    return HttpResponse(upstream.content)


def base_is_the_caller_s(request):
    # NEGATIVE. The caller's value in the BASE argument is an ordinary whole-value
    # destination, and it is already claimed by the channel's own rule at the client
    # call below -- this line is not where the reference resolution matters.
    fixed = urljoin(ORIGIN, "/health")
    upstream = requests.request("GET", fixed, timeout=10)
    return HttpResponse(upstream.content)


urlpatterns = [
    re_path(r"^proxy$", proxy, name="proxy"),
    re_path(r"^joined$", joined_whole, name="joined"),
    re_path(r"^concat$", concatenated, name="concat"),
    re_path(r"^health$", base_is_the_caller_s, name="health"),
]
