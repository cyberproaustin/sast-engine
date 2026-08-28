"""The second dispatch table, and the reason `history` resolves to nothing.

Two tables in one program declare `history`. The URLconf's key does not say which, and a
reader that picked one would bind `/admin/pages/<page_id>/history/` to a body that address
does not run. AMBIGUITY RESOLVES TO NOTHING: the route stays enumerated and carries no
handler, which is a gap a maintainer can see rather than a claim they cannot check.
"""

from django.utils.functional import cached_property

from snippets.views import PageEditView, SnippetHistoryView


class SnippetViewSet:
    history_view_class = SnippetHistoryView
    edit_view_class = PageEditView

    def construct_view(self, view_class, **kwargs):
        return view_class.as_view(**kwargs)

    @cached_property
    def history_view(self):
        return self.construct_view(self.history_view_class)

    @cached_property
    def detail_view(self):
        return self.construct_view(self.edit_view_class)

    @cached_property
    def views(self):
        return {
            "history": self.history_view,
            "snippet_detail": self.detail_view,
        }
