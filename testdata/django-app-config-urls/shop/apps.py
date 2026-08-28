"""The root application, which mounts the others by the label each registered under."""
from django.apps import AppConfig, apps
from django.urls import include, path


class Shop(AppConfig):
    # No `label`, so Django derives one from the last component of `name` -- which is what
    # the root URLconf asks `get_app_config` for.
    name = "shop"

    def ready(self):
        # Django's own place to resolve what an application needs at start-up. An
        # attribute assigned here is as much a declaration as a class-level one: `ready()`
        # runs before the first URLconf is built.
        self.catalogue_app = apps.get_app_config("catalogue")
        self.dashboard_app = apps.get_app_config("dashboard")

    def get_urls(self):
        return [
            # Two spellings of one mount. An app config's `urls` is a three-tuple whose
            # first element is the pattern list, and applications write both.
            path("catalogue/", self.catalogue_app.urls),
            path("dashboard/", include(self.dashboard_app.urls[0])),
        ]
