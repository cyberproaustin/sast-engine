"""A URLconf that mounts its neighbours as MODULES under aliases.

`include(console_reports_urls)` looks like `include(some_local_list)` and is not one: the
name is a module this file imported, and the routes are in another file entirely. wagtail
writes its whole admin this way, and every route below such a mount was enumerated at the
prefix of the file that WROTE it rather than the one it is served at -- `/locked/` for a
report that answers at `/admin/reports/locked/`, an address that does not exist.
"""
from django.urls import include, path

from console.urls import audit as console_audit_urls
from console.urls import reports as console_reports_urls

urlpatterns = [
    path("reports/", include(console_reports_urls)),
    path("audit/", include(console_audit_urls)),
]
