from flask import Flask, request

app = Flask(__name__)


@app.route("/mode")
def mode():
    # POSITIVE. `is` asks whether two strings are the same OBJECT. Python interns some
    # strings and not others, so the answer depends on how the value was built rather
    # than on what it says -- and this check silently stops working the day the value
    # arrives from a database instead of a literal.
    mode = request.args["mode"]
    if mode is "admin":
        return "admin mode"
    return "normal mode"


@app.route("/mode-equal")
def mode_equal():
    # NEGATIVE. Equality asks what the string SAYS, which is the question that was meant.
    if request.args["mode"] == "admin":
        return "admin mode"
    return "normal mode"


@app.route("/missing")
def missing():
    # NEGATIVE. Identity against None is the correct idiom and the recommended one: there
    # is exactly one None, so identity is the question. The rule excludes it by requiring
    # a string, and excludes numbers for the same reason -- small integers are interned
    # where strings are not, so `x is 5` is a different question with a different answer.
    value = request.args.get("mode")
    if value is None:
        return "missing"
    return value
