"""The mounted URLconf. It carries no trace of the prefix it is served under."""
from django.urls import path

from billing.reports import views

urlpatterns = [
    path("export/<int:pk>/", views.export),
    path("summary/", views.summary),
]
