from markupsafe import escape
from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/search")
def search():
    # The handler is not where this is decided. It hands named values to a view, and the
    # VIEW decides which of them are escaped -- which is why reading only this file reads
    # the half where nothing happens.
    return render_template("results.html", query=request.args["q"], count=3)


@app.route("/profile")
def profile():
    return render_template("profile.html", user={"name": request.args["name"]})


@app.route("/about")
def about():
    # NEGATIVE. Nothing the caller sent reaches this view.
    return render_template("about.html", updated="2026-01-01")


@app.route("/report")
def report():
    # NEGATIVE, and a STATED MISS rather than a safe line. The context is spread from a
    # dictionary built elsewhere, so the map from a template's variable names to the
    # values behind them does not exist here -- and naming a file on a guess is worse
    # than saying nothing.
    return render_template("results.html", **build_context())


def build_context():
    return {"query": request.args["q"], "count": 1}


@app.route("/comment")
def comment():
    # NEGATIVE. Escaped before it ever reaches the view, so the `| safe` filter receives
    # text that can no longer be markup.
    return render_template("comment.html", body=escape(request.args["body"]))
