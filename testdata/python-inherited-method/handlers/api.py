"""The registered classes. Neither carries the request handling it runs."""
from handlers.base import APIHandler


class SearchAPIHandler(APIHandler):
    required_scopes = ["read:checks"]

    def post(self):
        term = self.parse_body()["term"]
        self.write(str(self.lookup(term)))


class ReportHandler(APIHandler):
    """NEGATIVE for the resolution order. This subclass OVERRIDES the inherited name, so
    `self.parse_body()` here is its own method: a fallback that fired before the
    enclosing class was consulted would attribute the base's body to a route that never
    reaches it."""

    def parse_body(self):
        return {"term": "fixed"}

    def post(self):
        term = self.parse_body()["term"]
        self.write(str(self.lookup(term)))


default_handlers = [
    (r"/api/search", SearchAPIHandler),
    (r"/api/report", ReportHandler),
]
