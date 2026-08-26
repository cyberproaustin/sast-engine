"""The base class every registered handler in this program answers through.

Registered nowhere itself, and nothing in the program names these methods in a way that
resolves without knowing what `self` IS -- which is the whole point of the shape and the
whole reason a frontend has to follow it.
"""
import json
import sqlite3

from tornado import web

DB = sqlite3.connect("hub.db")


class APIHandler(web.RequestHandler):
    def parse_body(self):
        # Reads the caller's data, and is reachable ONLY through `self.parse_body()`
        # written in a subclass in another module. No route registers this class, and no
        # verb of this class calls it: an enumeration that stops at the registered class
        # accounts for neither this method nor the request data it handles.
        return json.loads(self.request.body)

    def lookup(self, term):
        # NEGATIVE. Parameterized, and deliberately so: what this corpus asserts is
        # REACHABILITY, and a corpus that also carried an injection would be asserting
        # the argument binding of an implicit receiver, which is a separate defect.
        cur = DB.cursor()
        cur.execute("SELECT * FROM checks WHERE name = ?", (term,))
        return cur.fetchone()
