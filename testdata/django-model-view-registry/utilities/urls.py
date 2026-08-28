"""The URL builder that reads the registry back, keyed by app label and model name."""
from django.urls import path

from utilities.views import registry


def get_model_urls(app_label, model_name, detail=True):
    paths = []
    try:
        views = [
            view
            for view in registry["views"][app_label][model_name]
            if view["detail"] == detail
        ]
    except KeyError:
        return []

    for config in views:
        view_ = config["view"]
        name = f"{model_name}_{config['name']}" if config["name"] else model_name
        url_path = f"{config['path']}/" if config["path"] else ""
        paths.append(path(url_path, view_.as_view(), name=name))

    return paths
