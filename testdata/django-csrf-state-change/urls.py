from django.urls import path

from .views import AddView, ReadOnlyView, app_auth_handoff


urlpatterns = [
    path("add/", AddView.as_view(), name="add"),
    path("read/", ReadOnlyView.as_view(), name="read"),
    path("app-auth/", app_auth_handoff, name="app-auth"),
]
