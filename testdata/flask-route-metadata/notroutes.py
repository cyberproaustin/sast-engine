"""What is written like a route decorator and is not one.

`patch` is an HTTP verb and it is also the name of the most widely used decorator in
Python testing. A surface that invents entry points is worse than one that misses them,
so a verb decorator on a receiver this file never watched being constructed is a route
only when its first argument is a PATH.
"""
from unittest import mock


@mock.patch("app.subprocess")
def replace_subprocess(fake):
    # NEGATIVE. Not a route: `mock` is no router, and `app.subprocess` is no path.
    return fake
