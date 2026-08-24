"""Flask registers routes in more ways than one decorator.

The model knew `@app.route` and nothing else, and enumerated ZERO entry points of a
1,012-function Flask forum while the frontend declared Flask support. A capability that is
declared and absent is worse than one that was never claimed: the declaration says the
engine can see this, the surface says there is nothing there, and the report says clean.

Two shapes, both core Flask. A MethodView subclass is dispatched by verb, so `get` handles
GET whatever the registration looks like. And `add_url_rule` registers a plain function
with no decorator anywhere.
"""
from flask import Flask, request
from flask.views import MethodView
import subprocess

app = Flask(__name__)


class Search(MethodView):
    def get(self):
        # Reached as GET /search, through a registration that never mentions a decorator.
        subprocess.check_output("locate " + request.args["q"], shell=True)
        return "ok"

    def post(self):
        return "ok"


def report():
    return "ok"


def register(bp):
    bp.add_url_rule("/search", view_func=Search.as_view("search"))
    bp.add_url_rule("/report", "report", report)
