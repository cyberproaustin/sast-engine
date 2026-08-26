"""Django registers a route by CALL, inside a list, in a file the handler knows nothing
about.

A frontend that knew Flask, FastAPI and aiohttp enumerated ZERO entry points of a
3,395-function Django application whose source holds 178 registrations -- and a surface
with no entry points reads exactly like a surface with nothing to say. Everything inside
those handlers was invisible, and every finding the engine did produce about that
application came from a rule that needs no entry point at all.

Every shape below is one that applications actually write: a function view, a class
dispatched by verb, a URLconf mounted from another module under a prefix, a list mounted
under a prefix in this same file, a path converter, a regex with a named group, and a
router that turns one line into six routes.
"""
from django.conf.urls import url
from django.urls import include, path, re_path
from rest_framework import routers

from front import views

router = routers.DefaultRouter()
# Six routes out of one line. The router expands a viewset into a list path and a detail
# path, and the class carries a method for each of them.
router.register("checks", views.CheckViewSet)

# Mounted below, under a prefix. This list is the only place these two routes are written
# and the mount is the only place their path is, which is why the prefix has to be
# resolved rather than assumed to be the file's root.
detail_urls = [
    path("log/", views.check_log),
    path("ping/<int:n>/", views.check_ping),
]

urlpatterns = [
    path("", views.index),
    path("checks/<uuid:code>/", include(detail_urls)),
    # One registration, two entry points: the class answers GET in `get` and POST in
    # `post`, and the URLconf says nothing about either.
    path("checks/<uuid:code>/edit/", views.CheckEdit.as_view()),
    re_path(r"^badge/(?P<slug>[\w-]+)/$", views.badge),
    path("api/v3/", include("api.urls")),
    path("api/", include(router.urls)),
    # NEGATIVE. Django removed the string form of a view in 2.0 and there is nothing here
    # to point an entry point at. Enumerating this route would put a handler in the surface
    # that this program does not contain, and an invented entry point is worse than a
    # missing one: it is the primary output, and every judgement rests on it.
    url(r"^legacy/$", "front.views.legacy"),
]
