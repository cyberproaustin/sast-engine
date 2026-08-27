"""Membership has two roles that the operator itself cannot distinguish.

Both weak digests below are written identically.  A denial-list membership establishes
whether the value is blocked; a cache membership asks whether work was already done.
The annotated module globals are intentional: losing that binding was why the SearXNG
comparison did not reach the IR when this gap was first measured.
"""
from hashlib import md5, sha256

from flask import Flask, request

app = Flask(__name__)

blacklist: list[str] = []
cache: dict[str, str] = {}


@app.route("/blocked")
def blocked():
    result_hash = md5(request.args["host"].encode()).hexdigest()
    # POSITIVE. The digest decides whether this value belongs to a denial set.
    return str(result_hash not in blacklist)


@app.route("/cached")
def cached():
    result_hash = md5(request.args["host"].encode()).hexdigest()
    # NEGATIVE. Character-for-character the same operator and digest, but this is the
    # ordinary spelling of a cache lookup and establishes no security property.
    return str(result_hash in cache)


@app.route("/strong")
def strong():
    result_hash = sha256(request.args["host"].encode()).hexdigest()
    # NEGATIVE. The container has the security role, but the digest is not weak.
    return str(result_hash in blacklist)
