"""The two routes the differential is stated between. The context builders below them are
registered nowhere, which is also true of saleor's: they run for every request, before
anybody knows whose it is.
"""
from django.urls import path

import app

urlpatterns = [
    path("reports/", app.get_report),
    path("reports/save/", app.update_report),
]
