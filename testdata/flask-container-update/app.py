"""`update` names a dict operation and a record operation with the same three words.

A channel described by method name alone made every `payload.update(request.form)` in a
Python codebase a record selector, and asking who owns an entry in a local dict is not a
question with an answer. This frontend has no type checker, so it answers from what the
author wrote down — an annotation, a literal, `**kwargs` — and stays silent otherwise.

Silence is not "not a container": the last handler here reaches `.update` on something
this frontend cannot type, and the flow is still reported. It simply cannot be certain
enough to gate.
"""
from flask import Flask, g, request

app = Flask(__name__)


@app.route("/log", methods=["POST"])
def log_request():
    # Literal — visibly a dict.
    payload = {}
    payload.update(request.form)
    return payload


@app.route("/search", methods=["GET"])
def search():
    # Annotation — the author said so.
    filters: dict[str, str] = build_defaults()
    filters.update(request.args)
    return filters


@app.route("/cache", methods=["GET"])
def cache_key(**kwargs):
    # `**kwargs` is a dict by the language's own rules.
    key = kwargs.copy()
    key.update(request.args)
    return key


@app.route("/me", methods=["GET"])
def whoami():
    # Present so that the caller's identity is observable somewhere in this program.
    # Without it the ownership policy reports that it cannot be evaluated at all, which
    # is correct but would leave the rest of this corpus untested.
    return {"id": g.user.id}


@app.route("/records", methods=["POST"])
def touch_record():
    # Nothing local says what this is. The flow is reported and cannot gate.
    store = get_store()
    store.update(request.form)
    return ""


def build_defaults() -> dict[str, str]:
    return {}


def get_store():
    return None
