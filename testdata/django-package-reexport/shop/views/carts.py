"""Where the cart view actually is."""
from django.http import HttpResponse


def cart_detail(request, pk):
    # NEGATIVE.
    return HttpResponse(str(pk))
