"""A URL capture bound to the handler's own parameter, which is where two of the three
Python frameworks here put it.

Every other framework this engine models hands the captures over as a property of
something and has a rule for it: aiohttp's `match_info`, Tornado's `path_args`, Django's
`request.GET`. Flask and Django's URLconf have no such object -- the parameter IS the
caller's string -- and no seeding strategy could state that shape, so
`@app.route("/run/<cmd>") def run(cmd)` followed by a shell call produced nothing at all.

The route is the evidence and it is exact. A parameter is caller data when the path this
handler is registered at declares a capture of that name, which is why nothing here needs
a list of parameter names to skip.
"""

import subprocess

import requests
from flask import Flask

app = Flask(__name__)


@app.route("/fetch/<target>")
def fetch(target):
    # POSITIVE. The whole destination, out of the path, into an outbound request.
    page = requests.get(target, timeout=10)
    return page.text


@app.route("/run/<cmd>")
def run(cmd):
    # POSITIVE. The textbook shape, and it was invisible: a capture composed into a
    # command line the shell interprets.
    return subprocess.check_output("ls " + cmd, shell=True)


@app.route("/report/<int:report_id>")
def report(report_id):
    # NEGATIVE, and the near miss the converter decides. The route resolves only for
    # `[0-9]+`, so the handler is never called with anything else in it -- which is the
    # same guarantee the engine already accepts from a numeric coercion, and for the same
    # reason: a number cannot carry syntax.
    return subprocess.check_output("cat /var/reports/" + str(report_id), shell=True)


@app.route("/tag/<slug:label>")
def tag(label):
    # NEGATIVE. `slug` resolves only for `[-a-zA-Z0-9_]+`: no quote, no slash, no space,
    # and no second slash to begin an authority with.
    return subprocess.check_output("grep " + label + " /var/tags", shell=True)


@app.route("/health")
def health(threshold=5):
    # NEGATIVE. A parameter with a default and no capture anywhere in the path. Nothing
    # about a handler's signature makes a value the caller's; the registration does.
    return subprocess.check_output("uptime -p " + str(threshold), shell=True)
