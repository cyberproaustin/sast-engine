"""What this application contributes to the admin, and what it does not.

Wagtail spells this file `wagtail_hooks.py` and an app registry imports it for its side
effects. The name of the file is not what makes it a registration: the decorator's string
key is, and the only thing that turns the key into an address is the `get_hooks` call in
`adminsite/urls.py`.
"""

from django.urls import include, path

from adminsite import hooks
from documents import admin_urls


@hooks.register("register_admin_urls")
def register_admin_urls():
    return [
        path("documents/", include(admin_urls, namespace="docs")),
    ]


@hooks.register("register_admin_menu_item")
def register_menu_item():
    # NEGATIVE. A hook under a key no URLconf reads back. It returns a menu entry, not
    # routes -- and a reader that fired on `@hooks.register` alone rather than on the join
    # would have to decide what to do with this one.
    return {"label": "Documents", "url": "/admin/documents/"}
