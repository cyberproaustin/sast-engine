"""The registrations, so that every view below is an enumerated entry point.

Without them the handlers are ordinary functions and a judgement about "the caller"
would have no caller to be about.
"""
from django.urls import path

from .views import (
    bookmark_detail,
    bundle_detail,
    preferences,
    search,
    share_bookmark,
    token_detail,
)

urlpatterns = [
    path("bookmarks/<str:bookmark_id>/", bookmark_detail),
    path("bundles/<str:bundle_id>/", bundle_detail),
    path("tokens/<str:token_id>/", token_detail),
    path("search/", search),
    path("preferences/", preferences),
    path("share/", share_bookmark),
]
