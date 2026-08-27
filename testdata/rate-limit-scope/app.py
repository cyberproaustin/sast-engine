"""A limiter's presence says nothing about the routes its predicate admits.

The application has one mounted limiter, which is the evidence that makes the two
positives worth reporting. The search route performs the same outbound work and is
silent because its path is admitted. The autocomplete route is outside that predicate.
The export route exercises the framework distinction: Flask ``request.args`` is the
query string and ``request.form`` is the POST body, so equal field names do not make the
limiter's query predicate cover the body-selected request.
"""

import requests
from flask import Flask, request

import autocomplete_backends
import limiter_methods

app = Flask(__name__)

AUTOCOMPLETE_BACKENDS = {
    "remote": autocomplete_backends.remote,
    "mirror": autocomplete_backends.mirror,
}


def search_autocomplete(name):
    backend = AUTOCOMPLETE_BACKENDS.get(name)
    return backend()


def limiter_hook():
    if request.path == "/search":
        for method in [limiter_methods]:
            method.filter_request(request)
    if request.path == "/export" and request.args.get("format") == "json":
        limiter_methods.filter_request(request)
    if request.path == "/query-export" and request.args.get("format") == "json":
        limiter_methods.filter_request(request)


app.before_request(limiter_hook)


@app.route("/search")
def search():
    reply = requests.get("https://search.example.test/query")
    return reply.text


@app.route("/autocompleter")
def autocompleter():
    return search_autocomplete(request.args.get("backend", "remote"))


@app.route("/export", methods=["POST"])
def export():
    if request.form.get("format") == "json":
        reply = requests.get("https://export.example.test/render")
        return reply.text
    return "html"


@app.route("/query-export")
def query_export():
    if request.args.get("format") == "json":
        reply = requests.get("https://export.example.test/render")
        return reply.text
    return "html"


@app.route("/healthz")
def healthz():
    return "ok"
