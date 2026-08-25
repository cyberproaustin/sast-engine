from flask import Flask, make_response, request

app = Flask(__name__)

DEFAULTS = {"httponly": True, "secure": True, "samesite": "Lax"}


@app.route("/login", methods=["POST"])
def login():
    # POSITIVE. No httponly keyword, and the keyword set is fully visible.
    r = make_response("ok")
    r.set_cookie("session", request.form["token"])
    return r


@app.route("/login-explicit", methods=["POST"])
def login_explicit():
    # POSITIVE. Written down.
    r = make_response("ok")
    r.set_cookie("jwt", request.form["token"], httponly=False)
    return r


@app.route("/login-crosssite", methods=["POST"])
def login_crosssite():
    # POSITIVE, never gating.
    r = make_response("ok")
    r.set_cookie("refresh_token", request.form["token"], httponly=True, samesite="None")
    return r


@app.route("/login-spread", methods=["POST"])
def login_spread():
    # NEGATIVE. ** hides which keywords are passed, so nothing can be concluded from
    # httponly not appearing.
    r = make_response("ok")
    r.set_cookie("session", request.form["token"], **DEFAULTS)
    return r


@app.route("/login-correct", methods=["POST"])
def login_correct():
    # NEGATIVE.
    r = make_response("ok")
    r.set_cookie("session", request.form["token"], httponly=True, secure=True, samesite="Lax")
    return r


@app.route("/csrf", methods=["POST"])
def csrf():
    # NEGATIVE. A double-submit token must be readable by script.
    r = make_response("ok")
    r.set_cookie("csrf_token", request.form["token"])
    return r
