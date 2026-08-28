"""The report URLconf, whose only mount is the hook nothing reads back."""

from django.urls import path

from reports import views

app_name = "reports"
urlpatterns = [
    path("locked/", views.LockedView.as_view(), name="locked"),
]
