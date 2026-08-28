"""The admin URLconf, whose own list is only half of what it serves.

The other half arrives from applications this file never imports: each one registers a
function under the string `register_admin_urls` and this loop splices what they return.
The prefix those routes are served under is written HERE and nowhere else.
"""

from django.urls import path

from adminsite import hooks
from adminsite import views

urlpatterns = [
    path("", views.HomeView.as_view(), name="home"),
]

for fn in hooks.get_hooks("register_admin_urls"):
    extra = fn()
    if extra:
        urlpatterns += extra

# NEGATIVE. A key nothing registers against reads back an empty list, so this loop mounts
# nothing at all. It exists so that the join is proved to run in both directions: a reader
# that fired on the loop alone would attribute some other application's routes here.
for fn in hooks.get_hooks("register_report_urls_unused"):
    urlpatterns += fn()
