import sqlite3

from flask import Flask, request

app = Flask(__name__)
conn = sqlite3.connect(":memory:")


@app.route("/search")
def search():
    # POSITIVE. `or ""` is how Python writes a default, and the caller's value is what
    # survives it whenever one was sent.
    term = request.args.get("q") or ""
    conn.cursor().execute("SELECT * FROM items WHERE name = '%s'" % term)
    return "ok"


@app.route("/walrus")
def walrus():
    # POSITIVE. The walrus binds and carries in one step.
    if (term := request.args.get("q")) is not None:
        conn.cursor().execute("SELECT * FROM items WHERE name = '%s'" % term)
    return "ok"


@app.route("/fixed")
def fixed():
    # NEGATIVE. Neither side of the default is caller-supplied.
    term = None or "everything"
    conn.cursor().execute("SELECT * FROM items WHERE name = '%s'" % term)
    return "ok"


@app.route("/parameterized")
def parameterized():
    # NEGATIVE. The caller's value is a parameter rather than part of the statement.
    term = request.args.get("q") or ""
    conn.cursor().execute("SELECT * FROM items WHERE name = ?", (term,))
    return "ok"
