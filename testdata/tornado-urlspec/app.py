"""Tornado does not register a route with a CALL.

A module declares a module-level list of TUPLES and the application collects those lists,
so the whole registration is a tuple sitting in a list -- not a call, not a decorator, and
with no name of its own for a frontend built out of call shapes to match. One real
application enumerated 9 entry points against 62 handler registrations, and all 9 of them
came out of its `examples/` directory rather than the application that ships.

This file holds the two shapes that are NOT tuples in a table: the call spelling Tornado
provides for building the same object outright, and the three-element form whose third
element is the dict the handler is constructed with.
"""
from tornado import web
from tornado.web import url

from handlers import api, pages
from handlers.pages import LogHandler, SearchHandler


def make_app():
    handlers = [
        # `url(...)` and `URLSpec(...)` build the object a tuple is shorthand FOR, so the
        # two are the identical registration and an application mixes them in one table.
        url(r"/search", SearchHandler),
        # A three-element tuple. The third element is the dict Tornado constructs the
        # handler with, and the capture in the pattern has no name of its own -- the
        # framework hands it to the verb method positionally.
        (r"/logs/([^/]+)", LogHandler, {"root": "/var/log"}),
    ]
    handlers.extend(pages.default_handlers)
    handlers.extend(api.default_handlers)
    return web.Application(handlers)
