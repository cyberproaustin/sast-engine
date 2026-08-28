"""The registrations, which are the only thing that makes any of these a view.

Three classes here and two of them are addressed. `UnroutedSearchView` is written the same
way as `OrderSearchView` and is deliberately absent from this list.
"""
from django.urls import path

from front import views

urlpatterns = [
    path("orders/", views.OrderSearchView.as_view()),
    path("orders/upload/", views.OrderUploadView.as_view()),
    path("orders/<int:pk>/", views.OrderDetailView.as_view()),
]
