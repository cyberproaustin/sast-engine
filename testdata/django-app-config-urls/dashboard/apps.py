"""A config whose views are wrapped in an access decorator at the registration."""
from django.apps import AppConfig
from django.contrib.auth.decorators import login_required
from django.urls import path

from oscarish.loading import get_class


class DashboardConfig(AppConfig):
    label = "dashboard"
    name = "shop.dashboard"

    def ready(self):
        self.range_reorder_view = get_class("dashboard.views", "RangeReorderView")
        # NEGATIVE. The second `ExportView` of the program. Registered here as well, so
        # neither registration can claim the name.
        self.export_view = get_class("dashboard.views", "ExportView")

    def get_urls(self):
        return [
            # 33 of oscar's 196 registrations wrap the view like this. What is REGISTERED
            # is still the view: the decorator delegates to it, and the handler the route
            # reaches is the one inside.
            path(
                "ranges/<int:pk>/reorder/",
                login_required(self.range_reorder_view.as_view()),
                name="range-reorder",
            ),
            path("export/", login_required(self.export_view.as_view()), name="export"),
        ]
