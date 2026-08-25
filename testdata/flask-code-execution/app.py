"""Python's own interpreters, reached from a request.

Every channel here was described in the model from the beginning and none of them had
ever matched, because the frontend emitted the bare name `eval` while the rule named
`builtins.eval`. A name that is neither defined in the file nor imported is the
language's own, and saying so is what connects the two.
"""
import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    # POSITIVE. eval compiles and runs whatever it is handed, with the module's globals
    # in reach -- so this is not arithmetic, it is a shell.
    return str(eval(request.args["expr"]))


@app.route("/run")
def run():
    # POSITIVE. exec is the same door for statements rather than expressions.
    exec(request.args["code"])
    return "ok"


@app.route("/load")
def load():
    # POSITIVE. The caller naming a module for the runtime to import chooses which code
    # runs, without any of it being written here.
    __import__(request.args["module"])
    return "ok"


@app.route("/safe-calc")
def safe_calc():
    # NEGATIVE. A literal is not a caller's choice.
    return str(eval("2 + 2"))


@app.route("/lookup")
def lookup():
    # NEGATIVE, and the reason `open` needed qualifying too: this reads a fixed file and
    # the caller chooses nothing about it.
    with open(os.path.join("/opt/app/data", "index.txt")) as fh:
        return fh.read()
