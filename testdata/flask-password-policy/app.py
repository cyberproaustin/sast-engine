from flask import Flask, request

app = Flask(__name__)


@app.route("/register", methods=["POST"])
def register():
    # POSITIVE. Six characters can be guessed offline in minutes once the hashes leak,
    # and the length a policy admits is the length people will use.
    password = request.form["password"]
    if len(password) < 6:
        return "too short", 400
    return "ok"


@app.route("/register-strict", methods=["POST"])
def register_strict():
    # NEGATIVE. Twelve is not below the line, so there is nothing to say.
    password = request.form["password"]
    if len(password) < 12:
        return "too short", 400
    return "ok"


@app.route("/register-max", methods=["POST"])
def register_max():
    # NEGATIVE, and the reason the NUMBER matters rather than the shape: this is the same
    # comparison read the other way. bcrypt silently truncates past 72 BYTES -- len()
    # counts characters, so this check is itself slightly wrong for non-ASCII passwords --
    # and rejecting long input is a real thing to do. Reporting it would be advice to
    # remove a check that exists for a reason.
    password = request.form["password"]
    if len(password) > 72:
        return "too long", 400
    return "ok"


@app.route("/register-configured", methods=["POST"])
def register_configured():
    # NEGATIVE, and a STATED MISS rather than a safe line. The minimum is read from
    # configuration, so the source does not say what it is -- and a rule about a
    # threshold cannot judge a threshold it cannot see.
    password = request.form["password"]
    if len(password) < app.config["MIN_PASSWORD_LENGTH"]:
        return "too short", 400
    return "ok"
