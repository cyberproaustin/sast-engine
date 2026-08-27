"""`add_url_rule` registers a route whose handler is an EXPRESSION, not a name.

The shape was already modelled and the argument test was not: `view_func` had to be a
bare `ast.Name`, so the one route an application registered as
`view_func=favicons.favicon_proxy` was the only Flask route in its tree that never
appeared on the surface.

Two of the three registrations below resolve to a function. The third does not, and it is
here because it is the case that matters: `favicon_proxy` is re-exported through a package
`__init__`, which this frontend's definition table does not follow. A route whose handler
cannot be resolved still exists at its address, and dropping it would make the enumerated
surface silently incomplete -- the one thing it must never be (ADR-009).
"""
from flask import Flask, request
from flask.views import MethodView
import subprocess

from searx import favicons
import handlers

app = Flask(__name__)


def local_search():
    # Reached as GET /local-search, registered by name.
    subprocess.check_output("locate " + request.args["q"], shell=True)
    return "ok"


class Preferences(MethodView):
    def get(self):
        return "ok"


# A bare name, which is the case that always worked.
app.add_url_rule("/local-search", "local_search", view_func=local_search)

# A module attribute, resolved through the import: the handler is in another file and the
# registration names it the way any Python program would.
app.add_url_rule("/report", methods=["GET", "POST"], view_func=handlers.report)

# A module attribute the definition table cannot follow, because the package re-exports
# it. The address is still an address.
app.add_url_rule("/favicon_proxy", methods=["GET"], endpoint="favicon_proxy",
                 view_func=favicons.favicon_proxy)

# NEGATIVE — a class-based view takes its verbs from its own methods, and those are
# already entry points. Recording the class as a route as well would double-count it.
app.add_url_rule("/preferences", view_func=Preferences.as_view("preferences"))
