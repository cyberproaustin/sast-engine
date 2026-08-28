"""The root URLconf, mounting by DOTTED STRING.

`include("billing.reports.urls")` is the most common thing a Django root URLconf says,
and it is a name resolved by Python's loader against the application's source root --
which is not the root a scanner is pointed at. plane's sources live under `apps/api/`, so
`plane.app.urls` matches no module id the frontend has, and a prefix table keyed by
equality answered none of that application's 399 registrations: 51 entry points were
enumerated, and 31 of those were the declarative fallback naming a class rather than a
path. The lookup is by suffix here for that reason, with the exact name tried first.
"""
from django.urls import include, path

urlpatterns = [
    path("api/v2/", include("billing.reports.urls")),
    # NEGATIVE. Nothing in this program is named that. A dotted string that reaches no
    # module mounts nothing -- inventing a route for it would put a handler in the surface
    # that does not exist.
    path("legacy/", include("billing.retired.urls")),
]
