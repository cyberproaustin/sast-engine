"""The documents admin URLconf. Nothing in this file says where it is served.

No `include()` anywhere in the program names this module directly. The one mount it has
is inside a function that a string key registers, three files away.
"""

from django.urls import path

from documents import views

app_name = "docs"
urlpatterns = [
    path("", views.IndexView.as_view(), name="index"),
    path("edit/<int:pk>/", views.EditView.as_view(), name="edit"),
]
