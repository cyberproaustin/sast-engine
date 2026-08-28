"""The PUBLIC document URLconf, mounted by the root URLconf at `documents/`.

It is here because it is the reason the address matters. Without the hook key, the admin
URLconf next door was enumerated at `documents/...` too -- so the admin's edit view was
claimed one segment away from a path this application really does serve, with a different
view behind it. A maintainer who opens that address finds a download.
"""

from django.urls import path

from documents import public

app_name = "docs_public"
urlpatterns = [
    path("<int:pk>/", public.serve, name="serve"),
]
