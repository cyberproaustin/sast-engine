"""The registry itself: a string key, functions registered against it, and a read-back.

Modelled on wagtail's `wagtail/hooks.py`. Nothing here is a route; the two halves of the
join are `register` and `get_hooks`, and every route in this application travels between
them as the return value of a function.
"""

_hooks = {}


def register(hook_name, fn=None):
    if fn is None:

        def decorator(inner):
            register(hook_name, inner)
            return inner

        return decorator

    _hooks.setdefault(hook_name, []).append(fn)


def get_hooks(hook_name):
    return _hooks.get(hook_name, [])
