"""A package that IS the URLconf, assembled out of its submodules under aliases.

`urlpatterns` is a value, and this file's is a splice of twenty-two other files' -- which
is exactly how plane writes `plane/app/urls/__init__.py`. Nothing here is an `include()`
and nothing here is a route: every registration is in a module this file names once, in
an import, under a different name.
"""
from .carts import urlpatterns as cart_urls
from .orders import urlpatterns as order_urls

urlpatterns = [
    *order_urls,
    *cart_urls,
]
