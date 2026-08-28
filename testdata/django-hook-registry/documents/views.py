"""The documents admin's views: a model each, and not one verb between them."""

from common import generic


class EditView(generic.EditView):
    model = "Document"


class IndexView(generic.IndexView):
    model = "Document"
