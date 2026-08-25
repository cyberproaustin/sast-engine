import secrets

from flask import Flask, make_response

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    # POSITIVE. The same judgement as the Express fixture, and the reason the threshold
    # lives on the rule rather than on the keyword: Flask counts SECONDS under a name
    # that looks like the one Express counts milliseconds under.
    response = make_response("ok")
    response.set_cookie("session", secrets.token_urlsafe(32), httponly=True, secure=True, max_age=31536000)
    return response


@app.route("/login-short", methods=["POST"])
def login_short():
    # NEGATIVE. Fifteen minutes, written in the unit this call actually uses.
    response = make_response("ok")
    response.set_cookie("session", secrets.token_urlsafe(32), httponly=True, secure=True, max_age=900)
    return response


@app.route("/theme", methods=["POST"])
def theme():
    # NEGATIVE. A cookie whose value is written into the source carries a flag rather
    # than a credential, and a preference that lasts a year is a feature.
    response = make_response("ok")
    response.set_cookie("theme", "dark", max_age=31536000)
    return response
