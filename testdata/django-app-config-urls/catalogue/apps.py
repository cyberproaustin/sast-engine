"""One application split across two configs, and a third that composes them.

`CatalogueConfig` is what is installed, and its `get_urls()` resolves to the first parent
in the MRO -- whose `super().get_urls()` reaches the second. The routes the running
application serves are the union of both, which is why both are read under the one label.
"""
from django.apps import AppConfig, apps
from django.urls import include, path, re_path

from oscarish.loading import get_class


class CatalogueOnlyConfig(AppConfig):
    label = "catalogue"
    name = "shop.catalogue"

    def ready(self):
        # The loader takes a module label and a class name, and neither is a path this
        # frontend can follow: the label is resolved against a search path at run time.
        # The CLASS NAME is the half that is decidable, and it is decidable only because
        # this program defines the name once.
        self.detail_view = get_class("catalogue.views", "ProductDetailView")
        self.index_view = get_class("catalogue.views", "CatalogueIndexView")
        # NEGATIVE. `ExportView` is defined in two modules of this program, so the name
        # names two classes and binding a route to either is a coin toss. A route at an
        # address the application does not serve is worse than no route at all.
        self.export_view = get_class("catalogue.views", "ExportView")

    def get_urls(self):
        urls = super().get_urls()
        urls += [
            path("", self.index_view.as_view(), name="index"),
            re_path(
                r"^(?P<product_slug>[\w-]*)_(?P<pk>\d+)/$",
                self.detail_view.as_view(),
                name="detail",
            ),
            path("export/", self.export_view.as_view(), name="export"),
        ]
        return urls


class CatalogueReviewsOnlyConfig(AppConfig):
    label = "catalogue"
    name = "shop.catalogue"

    def ready(self):
        self.reviews_app = apps.get_app_config("reviews")

    def get_urls(self):
        return [
            re_path(
                r"^(?P<product_pk>\d+)/reviews/",
                include(self.reviews_app.urls[0]),
            ),
        ]


class CatalogueConfig(CatalogueOnlyConfig, CatalogueReviewsOnlyConfig):
    """The composite the application actually installs."""


class ReviewsConfig(AppConfig):
    label = "reviews"
    name = "shop.catalogue.reviews"

    def ready(self):
        self.vote_view = get_class("catalogue.views", "ReviewVoteView")

    def get_urls(self):
        return [
            # Served at `catalogue/<product_pk>/reviews/<pk>/vote/`, and only the
            # composition of three configs says so.
            path("<int:pk>/vote/", self.vote_view.as_view(), name="vote"),
        ]
