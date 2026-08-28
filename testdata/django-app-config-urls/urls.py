"""The whole URLconf of an application whose routes are never written in a list.

django-oscar has no module-level `urlpatterns` anywhere in its 828 Python files. Every
application is a CLASS; each contributes its routes by overriding `get_urls()`, points
each one at an attribute it resolved by name in `ready()`, and is mounted by LABEL from
another config's `get_urls()`. The registration, the view it reaches and the prefix it is
served under are three facts in three files, and none of them is a literal at the point
where it is read: 219 declared routes enumerated 30, while 279 functions reading caller
input sat behind nothing.

This file is the only place the chain touches the ground.
"""
from django.apps import apps
from django.urls import include, path

urlpatterns = [
    # The root mount. Everything below is reached through `Shop.get_urls()`, and every
    # path in this program is this prefix plus what the chain of configs composes.
    path("", include(apps.get_app_config("shop").urls[0])),
]
