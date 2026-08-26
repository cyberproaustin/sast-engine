"""Not a router. The point of the negative in admin.py: `register` is an ordinary word."""

_handlers = {}


def register(name, handler):
    _handlers[name] = handler
