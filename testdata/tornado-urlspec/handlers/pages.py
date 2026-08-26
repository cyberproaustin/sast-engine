"""Handlers, and the module-level tuple table that is Tornado's whole route idiom.

The name `default_handlers` is a convention of the framework's own documentation and
nothing more -- an application is free to build its table anywhere and call it anything --
so what identifies one is the SHAPE: a pattern that is a path, and a class that answers a
request. Nothing here holds any trace of where it is served.
"""
import json
import subprocess

from tornado import web

from handlers.base import DB


class SearchHandler(web.RequestHandler):
    """One registration, two entry points. Tornado dispatches GET to `get` and POST to
    `post`, and the registration says nothing about either."""

    def get(self):
        # NEGATIVE. The same class, the verb that only reads.
        self.write(self.request.uri)

    def post(self):
        # POSITIVE. The caller's data is on the HANDLER: a verb method's first parameter
        # is `self` and there is no request parameter at all, so a rule that reads the
        # first parameter of a handler finds the handler itself here.
        term = json.loads(self.request.body)["term"]
        cur = DB.cursor()
        cur.execute("SELECT * FROM checks WHERE name LIKE '%" + term + "%'")
        self.write("ok")


class LogHandler(web.RequestHandler):
    def get(self, name):
        # POSITIVE. Registered by a THREE-element tuple, and the capture in its pattern
        # has no name -- Tornado puts the positional captures in `path_args`, which is the
        # same caller-supplied data by a second route.
        out = subprocess.check_output("tail -n 50 /var/log/" + self.path_args[0], shell=True)
        self.write(out)


class BadgeHandler(web.RequestHandler):
    def get(self, slug):
        # NEGATIVE. Registered through a NAMED group, which is the parameter Tornado
        # passes to the verb method as a keyword argument.
        self.write(slug)


class HealthHandler(web.RequestHandler):
    """No verb at all. A handler that answers every request the same way writes `prepare`,
    which runs ahead of whichever verb arrived, and a WebSocket handler answers in `open`
    and `on_message` and has no verb to be named after."""

    def prepare(self):
        self.write("ok")


class MetricsHandler(web.RequestHandler):
    """No verb and no request hook either. The base that has them is Tornado's own, which
    this program does not contain, so there is nothing left to resolve."""

    def render_metrics(self):
        return "hub_up 1"


class ProbeHandler(web.RequestHandler):
    """Registered only by the test module, which is why nothing below reaches this."""

    def post(self):
        cur = DB.cursor()
        cur.execute("DELETE FROM checks WHERE name = '" + self.request.body + "'")


default_handlers = [
    (r"/badge/(?P<slug>[\w-]+)", BadgeHandler),
    (r"/health$", HealthHandler),
    (r"/metrics$", MetricsHandler),
]
