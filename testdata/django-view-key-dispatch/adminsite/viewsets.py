"""The dispatch table, and the two hops between a key and a class.

Every name here is a literal and none of them is in the URLconf:

    views = {"edit": self.edit_view}     the key, and the attribute that answers it
    def edit_view(self): ...             a property that wraps whatever the class holds
    edit_view_class = PageEditView       the class, imported by THIS module

Eleven other classes in wagtail are called `EditView`, so the last hop is resolved against
the import table of the file that wrote it. `snippets/viewsets.py` in this corpus defines
another `PageEditView` with a live command injection of its own, reachable from no route:
a resolver that matched the bare name would report it at an address it does not answer.
"""

from django.utils.functional import cached_property

from pages.edit import PageEditView
from pages.listing import PageIndexView
from pages.publish import PagePublishView


class BaseViewSet:
    """The generic half. Its property is what `index` resolves through."""

    index_view_class = None

    def construct_view(self, view_class, **kwargs):
        return view_class.as_view(**kwargs)

    @property
    def index_view(self):
        return self.construct_view(self.index_view_class)

    def get_view_by_name(self, name):
        return self.views[name]


class PageViewSet(BaseViewSet):
    edit_view_class = PageEditView
    publish_view_class = PagePublishView
    # Overridden here. The property that reads it lives on the base, and Python resolves
    # the attribute on the instance's own class -- so `index` is this one.
    index_view_class = PageIndexView

    @cached_property
    def edit_view(self):
        return self.construct_view(self.edit_view_class)

    @cached_property
    def publish_view(self):
        return self.construct_view(self.publish_view_class)

    @cached_property
    def history_view(self):
        return self.construct_view(self.index_view_class)

    @cached_property
    def views(self):
        return {
            "edit": self.edit_view,
            "publish": self.publish_view,
            "index": self.index_view,
            "history": self.history_view,
        }
