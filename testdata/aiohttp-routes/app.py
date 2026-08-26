"""aiohttp registers a route by CALL, not by decorator.

A frontend that knew only decorators and `add_url_rule` enumerated ZERO routes of an
entire application -- and the report still looked complete, because a surface with no
entry points reads exactly like a surface with nothing to say. Everything inside those
handlers was invisible, a SQL injection among it.
"""
from aiohttp import web

from sqli import views


def setup_routes(app: web.Application):
    app.router.add_route("GET", "/students/", views.students)
    app.router.add_post("/students/new", views.create_student)


def build():
    # POSITIVE, and a second framework making the same decision Flask makes: the debug
    # middleware answers a failed request with the traceback and the local variables of
    # every frame.
    app = web.Application(debug=True)
    setup_routes(app)
    return app
