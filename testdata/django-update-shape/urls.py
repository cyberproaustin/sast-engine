from django.urls import path

from .views import merge_payload, update_unknown, update_widget, whoami

urlpatterns = [
    path("merge/", merge_payload),
    path("widgets/", update_widget),
    path("unknown/", update_unknown),
    path("me/", whoami),
]
