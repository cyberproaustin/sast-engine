import os

from flask import Flask, request

from helpers import run_and_wrap, wrap, wrap_literal

app = Flask(__name__)


@app.route("/reached")
def reached():
    # POSITIVE, and it is the CALL that matters rather than the property. The shell is
    # inside `run_and_wrap`, so nothing here reaches it unless the call written under the
    # property read was recorded at all.
    return run_and_wrap(request.args["host"]).value


@app.route("/carried")
def carried():
    # POSITIVE. The property read off the call's result carries what the call was given,
    # exactly as `parsed = wrap(host); parsed.value` always did -- which is what `f(x).y`
    # means.
    host = wrap(request.args["host"]).value
    os.system(f"ping -c 1 {host}")
    return host


@app.route("/literal")
def literal():
    # NEGATIVE. The same shape with nothing of the caller's in it: visiting the base of a
    # property read must record the call, not invent a source.
    host = wrap_literal("localhost").value
    os.system(f"ping -c 1 {host}")
    return host
