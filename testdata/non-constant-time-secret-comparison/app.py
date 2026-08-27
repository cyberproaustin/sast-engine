"""One caller-versus-secret equality and constant-time/ordinary controls.

The positive preserves JupyterHub's helper shape: a Tornado-style handler supplies the
caller's XSRF argument and its own stored token.  Neither the word token nor an equality
operator is enough alone.  The two operands are independently classified, which keeps
the ordinary comparisons below silent.
"""
import hmac
import secrets

from django.utils.crypto import constant_time_compare
from flask import Flask, request

app = Flask(__name__)


def check_xsrf_cookie(handler):
    token = handler.get_argument("_xsrf", None)
    # POSITIVE. The caller chose token; xsrf_token is the server's runtime reference.
    if token != handler.xsrf_token:
        return "forbidden", 403
    return "ok"


@app.route("/xsrf")
def xsrf():
    return check_xsrf_cookie(request)


@app.route("/hmac-safe")
def hmac_safe():
    # NEGATIVE. All three Python constant-time spellings are calls, not equality.
    supplied = request.headers["Authorization"]
    expected = hmac.new(b"server-secret", request.data, "sha256").hexdigest()
    return {
        "hmac": hmac.compare_digest(supplied, expected),
        "secrets": secrets.compare_digest(supplied, expected),
        "django": constant_time_compare(supplied, expected),
    }


@app.route("/confirmation", methods=["POST"])
def confirmation():
    # NEGATIVE. The caller supplied both values, so timing reveals nothing they did not
    # choose themselves; this is a confirmation field, not a secret check.
    return str(request.form["token"] == request.form["token_confirmation"])


@app.route("/ordinary")
def ordinary():
    # NEGATIVE. Caller input compared with an ordinary runtime value has no secret side.
    requested = request.args["format"]
    configured = app.config.get("OUTPUT_FORMAT")
    return str(requested == configured)
