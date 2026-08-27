"""A `try` chooses between paths, and the Python frontend used to say none of it.

`ast.Try` fell through to the generic child walk: the body, every handler and the
`finally` were lowered straight-line into one block. A handler's calls then looked like
the next thing after the body rather than what runs INSTEAD of the rest of it, so no rule
that reads the shape of the graph could say anything about the commonest refusal shape
Python has -- reject inside a `try`, carry on after it.

The exception edge belongs to the try REGION and not to any statement inside it. Hanging
it on the first block of the BODY makes a handler the successor of whatever the body
ended up doing, and a body that ends in `return` terminates that very block -- so the
handler becomes the one thing that unavoidably follows the refusal. TypeScript was
corrected for exactly that; this corpus is what keeps Python from repeating it.

The negatives are the shapes a wrong edge makes look wrong. `/archives` returns on every
path through the body, so the line after the `try` is reached only from the `except` --
nothing there follows the refusal. `/reports` is a bare `finally` with no handler at all,
which is a `try` with no exception edge to hang anywhere.
"""
from flask import Flask, current_app, g, jsonify, request

app = Flask(__name__)


@app.route("/exports/<export_id>", methods=["POST"])
def start_export(export_id):
    # POSITIVE -- a refusal built inside a `try` and walked past. The branch below
    # returns the very same construction; this one leaves it on the floor, so the
    # ownership check runs, decides against the request, and the export is queued
    # anyway. Being inside a `try` is not a defence.
    try:
        if not owns_export(export_id):
            jsonify({"error": "not your export"})
        queue_export(export_id)
        return jsonify({"queued": export_id})
    except ValueError:
        return jsonify({"error": "export failed"})


@app.route("/imports", methods=["POST"])
def start_import():
    # POSITIVE -- a handler genuinely reached. The `raise` written in the try body is the
    # one thing that DOES reach an `except`, and the detail it carries goes into the
    # response. An edge deleted rather than moved would make this handler dead code and
    # take a true finding with it.
    try:
        name = request.form["name"]
        if not name.endswith(".csv"):
            raise ValueError("no import named " + name)
        return jsonify(load_import(name))
    except ValueError as err:
        return jsonify({"error": str(err)})


@app.route("/archives", methods=["GET", "POST"])
def archives():
    # NEGATIVE -- every path through the body returns, so the line after the `try` is
    # reached only from the `except`. Nothing here follows the refusal: the refusal
    # returns, and the handler answers a different path. This is the shape that was
    # reported twice at error level in a production repository when the exception edge
    # hung on the body instead of the region.
    try:
        if request.method == "POST":
            return jsonify(create_archive(request.form["name"]))
        return jsonify({"error": "method not allowed"})
    except OSError:
        current_app.logger.warning("archive failed")
    return jsonify({"error": "archive unavailable"})


@app.route("/status")
def status():
    # NEGATIVE, and the smallest version of the shape the exception edge must never be
    # hung on. The body is one `return` and nothing else, so the block it lowers to
    # leaves the function -- and an edge to the handler drawn from THAT block says a
    # response is followed by a second response. Python writes this handler more often
    # than it writes any other.
    try:
        return jsonify(fetch_status())
    except OSError:
        return jsonify({"error": "status unavailable"})


@app.route("/reports")
def reports():
    # NEGATIVE -- a bare `finally` with no handler at all. The finally runs on every path
    # and it closes a connection; it does not answer, and there is no handler for an
    # exception edge to reach.
    conn = connect()
    try:
        return jsonify(fetch_reports(conn))
    finally:
        conn.close()


def owns_export(export_id):
    return export_id in current_app.config["EXPORTS"]


def queue_export(export_id):
    current_app.config["QUEUE"].append(export_id)


def load_import(name):
    raise ValueError("driver: no such import " + name)


def create_archive(name):
    return {"archive": name}


def connect():
    return g.db


def fetch_status():
    return {"ok": True}


def fetch_reports(conn):
    return conn.cursor().execute("SELECT id FROM reports").fetchall()
