"""Rules the model has shipped for a long time and no fixture had ever exercised.

Written after a diagnostic asked the obvious question -- for every symbol the model
names, does any lowered program ever produce it -- and answered that 130 of 304 had
never been seen. Most of those are libraries no corpus happens to use. Some were a
spelling the frontend never emits, which is a rule that cannot fire and looks exactly
like a rule that found nothing: `builtins.open` was one, and it hid Python's most
common file API.

Every finding here is one the model already described. The point of the file is that
the description and the frontend agree.
"""
import hashlib
import pickle
import subprocess
import urllib.request

import jinja2
import yaml
from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/ping")
def ping():
    # POSITIVE. The modern spelling of running a subprocess, and the one no fixture had.
    subprocess.run("ping -c 1 " + request.args["host"], shell=True)
    subprocess.call("traceroute " + request.args["host"], shell=True)
    subprocess.Popen("dig " + request.args["host"], shell=True)
    return "ok"


@app.route("/restore")
def restore():
    # POSITIVE. Both spellings reconstruct arbitrary objects from bytes a caller chose.
    pickle.loads(request.get_data())
    yaml.unsafe_load(request.args["doc"])
    return "ok"


@app.route("/fetch")
def fetch():
    # POSITIVE. The caller chooses which host this server talks to.
    urllib.request.urlopen(request.args["url"])
    return "ok"


@app.route("/download")
def download():
    # POSITIVE. The caller chooses which file leaves the machine.
    return send_file(request.args["name"])


@app.route("/render")
def render():
    # POSITIVE. A template compiled from a caller's text is a caller's program: Jinja
    # expressions reach attributes, and attributes reach the interpreter.
    return jinja2.Template(request.args["tpl"]).render()


@app.route("/digest")
def digest():
    # POSITIVE, and a gap this file found rather than exercised. The weak-hash rules
    # covered `hashlib.new("sha1")` and `crypto.createHash("sha1")` and nothing else, so
    # the direct form -- the spelling in every Python tutorial ever written -- was not
    # reported at all. The algorithm is named just as plainly; it is the function rather
    # than a string.
    return hashlib.sha1(b"fixed").hexdigest()
