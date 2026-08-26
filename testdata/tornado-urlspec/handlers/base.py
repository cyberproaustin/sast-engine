"""The base class a whole file of registered handlers answers in.

A Tornado handler very often names no verb of its own: the subclass carries the model and
the permission check, and the base carries `get` and `post`. A registration that stops at
the class it names reaches nothing at all -- and in a large application that is most of
the handlers, because the shape exists precisely so the verbs are written once.
"""
import json
import sqlite3

from tornado import web

DB = sqlite3.connect("hub.db")


class APIHandler(web.RequestHandler):
    """Registered nowhere. Every route that reaches this is a route to a SUBCLASS."""

    def get(self):
        # NEGATIVE. Reading the request line is not a weakness; where it goes is.
        self.write(self.request.path)

    def post(self):
        # POSITIVE. Tornado hangs the request off the HANDLER rather than passing it in,
        # so the caller's data is at `self.request` and the verb method's only parameter
        # is `self`. This method is in the surface ONLY if a registration that names a
        # subclass with no verbs of its own resolves one level up into this class.
        name = json.loads(self.request.body)["name"]
        cur = DB.cursor()
        cur.execute("INSERT INTO users (name) VALUES ('" + name + "')")
        self.write("ok")
