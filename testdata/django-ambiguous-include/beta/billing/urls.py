"""The other module `billing.urls` could mean. Same dotted tail, different tree."""
from django.urls import path

from beta.billing import views

urlpatterns = [
    path("charge/", views.charge),
]
