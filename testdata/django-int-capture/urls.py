"""Django's commonest detail route, and what its converter is allowed to decide.

`path("thing/<int:pk>/", ...)` is how the largest Python web framework writes a route that
operates on one row. The converter was read as a sanitizer for EVERY context, which is
right for an interpreter -- an integer carries no quote, no line break and no path
separator -- and wrong for record selection, because an IDOR is precisely the caller
sending a different integer. So Django's most ordinary route carried no caller data into
any ownership judgement at all, which the django-manager-lookup corpus records as the
second reason that shape has less reach than its call count suggests.

Both directions are here. The `<int:>` capture reaches a record operation and is reported,
reaches a SQL statement and is not, and the `<str:>` control reaches the same SQL statement
and is -- so what the corpus proves is that the converter decides, and that what it decides
depends on where the value lands.
"""
from django.urls import path

from views import note_delete, note_delete_owned, note_sql, note_sql_slug

urlpatterns = [
    path("notes/<int:pk>/delete/", note_delete),
    path("notes/<int:pk>/delete-owned/", note_delete_owned),
    path("notes/<int:pk>/sql/", note_sql),
    path("notes/<str:slug>/sql/", note_sql_slug),
]
