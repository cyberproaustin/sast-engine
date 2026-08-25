from flask import Flask, request

app = Flask(__name__)
current_user = None
SESSIONS = {}


@app.route("/login", methods=["POST"])
def login():
    # POSITIVE. Python makes this unambiguous: the `global` declaration is what turns an
    # assignment into a write to state the whole process shares. Without it the same
    # statement makes a local and touches nothing.
    global current_user
    current_user = request.form["email"]
    return "ok"


@app.route("/login-keyed", methods=["POST"])
def login_keyed():
    # NEGATIVE. A module-level container keyed by something is a cache.
    SESSIONS[request.form["email"]] = True
    return "ok"


@app.route("/login-local", methods=["POST"])
def login_local():
    # NEGATIVE. No declaration, so this is a local and the module-level name is untouched.
    current_user = request.form["email"]
    return str(bool(current_user))


@app.route("/whoami")
def whoami():
    return str(current_user)
