"""The URLconf, which names keys and never a view.

Every route in this application is `include(get_model_urls(...))` around a pair of
strings. The list the call returns is assembled from decorators in `views.py`, so the
route-to-view binding is decorator to registry to call and is never written down.
"""
from django.urls import include, path

from utilities.urls import get_model_urls

app_name = "dcim"

MODEL = "region"

urlpatterns = [
    path("regions/", include(get_model_urls("dcim", "region", detail=False))),
    path("regions/<int:pk>/", include(get_model_urls("dcim", "region"))),
    # NEGATIVE. The key is a name rather than a literal. Which registrations it selects
    # depends on a value, and this frontend has no evaluator: a guess here mounts an
    # arbitrary set of views at an address of its own choosing.
    path("models/<int:pk>/", include(get_model_urls("dcim", MODEL))),
    # NEGATIVE. `Device` is a model name two applications of this program define, so the
    # decorator that named it filed nothing this key can reach.
    path("devices/<int:pk>/", include(get_model_urls("dcim", "device"))),
]
