"""A table of registered handlers, not one of which names a verb.

This is the shape that makes inheritance load-bearing rather than a nicety: every class
here is a real route, and the method a request actually reaches is in another file.
"""
from handlers.base import APIHandler


class UserAPIHandler(APIHandler):
    """A subclass that adds a permission scope and nothing else."""

    required_scopes = ["admin:users"]


class GroupAPIHandler(APIHandler):
    required_scopes = ["admin:groups"]


default_handlers = [
    # A named group is the parameter Tornado passes as a keyword argument. Both routes
    # answer in `APIHandler.post`, one file up the chain.
    (r"/api/users/(?P<name>[\w-]+)", UserAPIHandler),
    (r"/api/groups/(?P<name>[\w-]+)", GroupAPIHandler),
]
