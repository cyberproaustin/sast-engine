from flask import Flask, make_response, request

app = Flask(__name__)

DEFAULTS = {"httponly": True, "secure": True, "samesite": "Lax"}


def mint_session(email):
    # The value stored is GENERATED here, which is what a login actually does. Using the
    # caller's own submission would be a different weakness in a corpus about a different
    # judgement -- and it was one, until the engine learned to read `form["token"]` as a
    # field called token rather than as an anonymous index.
    return f"s-{email}-fixed"


@app.route("/login", methods=["POST"])
def login():
    # POSITIVE. No httponly keyword, and the keyword set is fully visible.
    r = make_response("ok")
    r.set_cookie("session", mint_session(request.form["email"]))
    return r


@app.route("/login-explicit", methods=["POST"])
def login_explicit():
    # POSITIVE. Written down.
    r = make_response("ok")
    r.set_cookie("jwt", mint_session(request.form["email"]), httponly=False)
    return r


@app.route("/login-crosssite", methods=["POST"])
def login_crosssite():
    # POSITIVE, never gating.
    r = make_response("ok")
    r.set_cookie("refresh_token", mint_session(request.form["email"]), httponly=True, samesite="None")
    return r


@app.route("/login-spread", methods=["POST"])
def login_spread():
    # NEGATIVE. ** hides which keywords are passed, so nothing can be concluded from
    # httponly not appearing.
    r = make_response("ok")
    r.set_cookie("session", mint_session(request.form["email"]), **DEFAULTS)
    return r


@app.route("/login-correct", methods=["POST"])
def login_correct():
    # NEGATIVE.
    r = make_response("ok")
    r.set_cookie("session", mint_session(request.form["email"]), httponly=True, secure=True, samesite="Lax")
    return r


@app.route("/csrf", methods=["POST"])
def csrf():
    # NEGATIVE. A double-submit token must be readable by script.
    r = make_response("ok")
    r.set_cookie("csrf_token", mint_session(request.form["email"]))
    return r
