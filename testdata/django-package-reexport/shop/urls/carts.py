"""The other submodule."""
from django.urls import path

from shop.views import cart_detail

urlpatterns = [
    path("carts/<int:pk>/", cart_detail),
]
