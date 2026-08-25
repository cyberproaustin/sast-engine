import sys

from flask import Flask, request

app = Flask(__name__)


@app.route("/plugins/add")
def add_plugin():
    # POSITIVE. Where the interpreter looks for modules is a security decision. A caller
    # who can put a directory at the front of it decides what the next import runs.
    sys.path.insert(0, request.args["dir"])
    import plugin  # noqa: F401

    return "ok"


@app.route("/plugins/reset")
def reset():
    # NEGATIVE. A fixed directory.
    sys.path.insert(0, "/opt/app/plugins")
    return "ok"
