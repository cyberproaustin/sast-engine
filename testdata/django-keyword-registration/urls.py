from django.urls import path, re_path

from views import ExampleList, ExampleDetail, plain_view

# Django's tutorial writes the first form. Django's own reference documentation writes the
# second, and a great many projects follow it. They are the same registration.
urlpatterns = [
    path("positional/", plain_view),
    path(route="keyword/", view=ExampleList.as_view()),
    path(view=ExampleDetail.as_view(), route="reordered/"),
    re_path(route=r"^regex/(?P<pk>\d+)$", view=plain_view),
    # Not a registration: no view at all, so nothing answers here.
    path(route="incomplete/"),
]
