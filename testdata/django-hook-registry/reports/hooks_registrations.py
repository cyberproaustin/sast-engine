"""NEGATIVE. Routes registered under a key nothing reads back.

The shape is identical to the documents application's: a decorator, a string, a function
returning a list of registrations. What is missing is the other half of the join -- no
`get_hooks("register_admin_report_urls")` exists anywhere in this program -- so these
routes are mounted by nothing and must NOT borrow the admin's prefix. `/reports/locked/`
is what this file states on its own, and `/admin/reports/locked/` would be a claim about
an address only the missing loop could have created.
"""

from django.urls import include, path

from adminsite import hooks
from reports import urls as reports_urls


@hooks.register("register_admin_report_urls")
def register_report_urls():
    return [
        path("reports/", include(reports_urls, namespace="reports")),
    ]
