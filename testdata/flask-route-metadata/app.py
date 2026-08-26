"""Wrong metadata is worse than a missing route.

A route that is enumerated with the wrong verb, the wrong framework or the wrong path is
not a smaller version of the truth -- it is a false statement about the surface, and every
question asked against it inherits the error. A GET-only label makes a whole class of
body-based bypasses unaskable: nobody asks what a POST body reaches when the surface says
no POST exists.

Flask defaults to GET when `methods=` is ABSENT. That default was being applied even where
the argument was present, so a search engine's five POST-capable routes were all recorded
GET-only. One decorator declaring two verbs is two entry points, not one.
"""
import os
import subprocess

from flask import Blueprint, Flask, request

app = Flask(__name__)

# A blueprint constructed UNDER a prefix. Every route registered on it is served below
# that prefix, and a path recorded without it names an address that answers nothing.
admin = Blueprint("admin", __name__, url_prefix="/admin")

# The prefix an operator configures and almost nobody changes. The default is the address
# for every deployment that leaves the variable unset, which is the same judgement the
# Django URLconf model already makes about a setting interpolated into a route.
service_prefix = os.environ.get("SERVICE_PREFIX", "/hub")


@app.route("/search", methods=["GET", "POST"])
def search():
    """POST /search and GET /search, from one decorator.

    POSITIVE. The query arrives in the BODY, which is a place the surface said this route
    did not read from, because the surface said this route did not accept POST.
    """
    query = request.form.get("q", "")
    subprocess.check_output("grep " + query + " /var/log/app.log", shell=True)
    return "ok"


@app.route("/health")
def health():
    # NEGATIVE for the verb: `methods=` is absent, so Flask's GET default is the right
    # answer here and stays the right answer.
    return "ok"


@admin.route("/purge", methods=("POST",))
def purge():
    """POSITIVE, at `/admin/purge` rather than `/purge`.

    A tuple declares verbs exactly as a list does, and the blueprint's own prefix is the
    first half of this route's address.
    """
    subprocess.check_output("rm -rf " + request.form["directory"], shell=True)
    return "ok"


@app.route(service_prefix + "/whoami")
def whoami():
    # The path is a concatenation over an environment variable, which used to lower to
    # `*`. It resolves to `/hub/whoami` for every deployment that leaves SERVICE_PREFIX
    # alone.
    return request.args.get("name", "")


def _runtime_prefix():
    return os.path.join("/", os.urandom(2).hex())


@app.route(_runtime_prefix() + "/callback")
def callback():
    # A prefix that genuinely cannot be read. The path is marked UNRESOLVED and names the
    # expression that stood in the way -- not `*`, which claims the route matches
    # everything and is a different and false statement.
    return "ok"
