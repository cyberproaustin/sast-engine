"""NEGATIVE. An ordinary class-based view registered with an argument.

`as_view("compact")` is not a keyed lookup: the receiver is the class itself, and the
string is a keyword this frontend does not read. The route resolves the way it always did.
"""

from django.http import HttpResponse


class SearchView:
    def get(self, request):
        return HttpResponse("results")
