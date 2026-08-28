"""The decorator that binds a view to a model, and the registry it writes into.

Nothing here is a route. What the decorator records is a KEY -- the model's app label and
its name -- and the URL builder in `utilities/urls.py` reads the same key back. Between the
two there is no expression naming both a path and a view, which is why a reader matching
`path(<literal>, <view>)` sees an `include` of a call and stops.
"""
from collections import defaultdict

registry = {"views": defaultdict(dict)}


def register_model_view(model, name="", path=None, detail=True, kwargs=None):
    def _wrapper(cls):
        app_label = model._meta.app_label
        model_name = model._meta.model_name
        if model_name not in registry["views"][app_label]:
            registry["views"][app_label][model_name] = []
        registry["views"][app_label][model_name].append(
            {
                "name": name,
                "view": cls,
                "path": path if path is not None else name,
                "detail": detail,
                "kwargs": kwargs or {},
            }
        )
        return cls

    return _wrapper
