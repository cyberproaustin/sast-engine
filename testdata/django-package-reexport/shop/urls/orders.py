"""One submodule of the URLconf package. Its view arrives through a re-export too."""
from django.urls import path

from shop.views import RefundView, order_index

urlpatterns = [
    path("orders/<int:pk>/refund/", RefundView.as_view()),
    path("orders/", order_index),
]
