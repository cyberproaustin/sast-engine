"""The package re-export every registered view imports its base through.

`from core.views import generic` and then `generic.ObjectListView` names a class this file
does not define and this package does not sit at. The dotted name an importer writes is
never the module id -- the source root is a directory inside the repository -- so the base
is resolved to a module of THIS program and then matched by name inside it.
"""
from core.views.generic.object_views import ObjectEditView, ObjectListView

__all__ = ("ObjectEditView", "ObjectListView")
