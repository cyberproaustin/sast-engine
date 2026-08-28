"""The registry the URLconf dispatches through, and nothing it resolves at import time.

`as_view` hands back a closure. Which viewset that closure asks depends on the page the
request names, so the class behind an address is chosen per REQUEST -- the one written
down is the default viewset, and that is the one the surface can honestly claim.
"""

from django.http import Http404


class PageViewSetRegistry:
    def __init__(self):
        self.by_type = {}

    def register(self, page_type, viewset):
        self.by_type[page_type] = viewset

    def as_view(self, view_name, **kwargs):
        def view_router(request, *args, **inner):
            viewset = self.by_type.get(inner.get("page_id"), base_page_viewset)
            try:
                view = viewset.get_view_by_name(view_name)
            except KeyError as err:
                raise Http404 from err
            return view(request, *args, **inner)

        return view_router


page_viewset_registry = PageViewSetRegistry()

from adminsite.viewsets import PageViewSet  # noqa: E402

base_page_viewset = PageViewSet()
