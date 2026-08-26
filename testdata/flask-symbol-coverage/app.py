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
import re
import subprocess
import urllib.request

import jinja2
import yaml
from flask import Flask, request, send_file

app = Flask(__name__)

EMAIL_RE = re.compile(r"^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+$")
SLUG_RE = re.compile(r"^[a-z0-9-]{1,64}$")


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
    # POSITIVE. The direct form of a weak hash -- the spelling in every Python tutorial
    # ever written, and the one the named-algorithm rules never covered. It is a finding
    # because the digest DECIDES something: it is compared against a recorded digest,
    # which is the program saying that the digest stands in for the bytes. Nothing about
    # the call changed; what changed is that there is now a second line to read.
    if hashlib.sha1(b"fixed").hexdigest() == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33":
        return "ok"
    return "no"


@app.route("/subscribe", methods=["POST"])
def subscribe():
    # POSITIVE, and the shape most email patterns on the internet have: a quantified
    # group whose body is itself quantified, so one input can be split between the inner
    # and outer repetition exponentially many ways. Compiled at module scope and used in
    # the handler, which is the normal way to write this and means the rule has to follow
    # the receiver through the compile step to see the pattern at all.
    if not EMAIL_RE.match(request.form["mail"]):
        return "bad", 400
    return "ok"


@app.route("/page/<slug>")
def page(slug):
    # NEGATIVE. The same caller-supplied string against a pattern that cannot churn.
    if not SLUG_RE.match(slug):
        return "no", 404
    return "ok"
