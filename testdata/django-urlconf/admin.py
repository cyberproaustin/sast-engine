"""Three registrations that are not routes.

Each wears the shape a route registration wears -- the word `register`, a class the program
defines, a string -- and none of them serves anything. What separates a route from the rest
is that a route always names a PATH and points at something that answers a request.
"""
from django.contrib import admin
from django.urls import register_converter

from front import signals, views
from front.models import Check


class SHA1Converter:
    regex = "[A-Fa-f0-9]{40}"

    def to_python(self, value):
        return value


class CheckAdmin(admin.ModelAdmin):
    list_display = ("code", "name")

    def get_queryset(self, request):
        return super().get_queryset(request)


# NEGATIVE. The admin registry takes a model and a class, and a router takes a path and a
# class -- the same word, and this one names no path.
admin.site.register(Check, CheckAdmin)

# NEGATIVE. A path and a callable, registered on something that is not a router. A viewset
# is a CLASS with methods a request reaches, and a signal handler is a function.
signals.register("check-saved", views.index)

# NEGATIVE. A converter is what a route's `<sha1:key>` is made OF rather than a route, and
# it is written as the same class and string in the same order.
register_converter(SHA1Converter, "sha1")
