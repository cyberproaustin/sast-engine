"""The page URLconf: every address is a literal and no view is.

This is wagtail's `wagtail/admin/urls/pages.py`, where 34 of the file's 35 registrations
name their handler with a string. The address side already resolved; the handler side
reached a registry object with no `views` on it and produced nothing at all, so 34 routes
of the admin -- edit, delete, publish, move, copy -- were declared and answered by nobody.
"""

from django.urls import path

from adminsite.registry import page_viewset_registry
from adminsite import search

app_name = "adminsite"
urlpatterns = [
    path(
        "pages/<int:page_id>/edit/",
        page_viewset_registry.as_view("edit", page_id_kwarg="page_id"),
        name="edit",
    ),
    path(
        "pages/<int:page_id>/publish/",
        page_viewset_registry.as_view("publish", page_id_kwarg="page_id"),
        name="publish",
    ),
    # The key whose property is declared on the BASE viewset and whose class attribute the
    # subclass overrides. Python resolves `self.index_view_class` on the instance's own
    # class, so this is `PageIndexView` and not the base's `ObjectListView`.
    path("pages/", page_viewset_registry.as_view("index", is_base_page=True), name="index"),
    # NEGATIVE. `history` is declared by two dispatch tables in this program. Neither
    # answers: binding the route to whichever the walk reached first is a claim that a
    # request to this address runs a body it does not run.
    path(
        "pages/<int:page_id>/history/",
        page_viewset_registry.as_view("history", page_id_kwarg="page_id"),
        name="history",
    ),
    # NEGATIVE. A key no dispatch table in this program declares. The route exists at this
    # address and the handler behind it is not written down anywhere a reader can see.
    path(
        "pages/<int:page_id>/export/",
        page_viewset_registry.as_view("export", page_id_kwarg="page_id"),
        name="export",
    ),
    # NEGATIVE. An ordinary class-based view whose `as_view()` takes an argument that is
    # not a dispatch key. The receiver is the class, and reading the argument as a key
    # would take a route that already resolves and hand it to a stranger.
    path("pages/search/", search.SearchView.as_view("compact"), name="search"),
]
