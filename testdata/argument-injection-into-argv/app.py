"""Argument vectors have an interpreter of their own: the option parser.

No shell appears in this corpus. The positives let a caller create an argv element that
begins with a dash, including the two collection-building forms production code used.
The negatives pin structural proofs that the option parser cannot consume the element:
a literal end-of-options marker before it, and removal of every possible leading dash.
"""
import shlex
import subprocess

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/account")
def account():
    name = request.args["name"]
    cmd = ["useradd"]
    cmd += [name]
    subprocess.Popen(cmd)
    return "queued"


@app.route("/files")
def files():
    parts = shlex.split(request.args["query"])
    if not parts[-1].isalnum():
        abort(400)
    cmd = ["find"]
    cmd.extend(parts)
    subprocess.Popen(cmd)
    return "queued"


@app.route("/words")
def words():
    parts = request.args["words"].split()
    cmd = ["indexer"]
    cmd.extend(parts)
    subprocess.run(cmd)
    return "queued"


@app.route("/account-safe")
def account_safe():
    name = request.args["name"]
    cmd = ["useradd", "--"]
    cmd += [name]
    subprocess.Popen(cmd)
    return "queued"


@app.route("/key-safe")
def key_safe():
    key = request.args["key"].lstrip("-")
    subprocess.Popen(["provision", key])
    return "queued"
