"""The same two SQL channels, on a second language, with no engine or policy change.

`cursor.execute(sql, params)` is the canonical parameterized call and the canonical
injection, depending only on which argument the caller's data ends up in. The channel
that finds the JavaScript case finds this one, because what it describes is the
operation rather than the library.
"""
from flask import Flask, g, request

app = Flask(__name__)


@app.route("/user")
def find_user():
    # Interpolated into the statement.
    cur = g.db.cursor()
    cur.execute("SELECT id, name FROM users WHERE login = '" + request.args["login"] + "'")
    return cur.fetchall()


@app.route("/user-by-id")
def find_user_by_id():
    # Same value, passed as a parameter. Not a finding.
    cur = g.db.cursor()
    cur.execute("SELECT id, name FROM users WHERE id = %s", (request.args["id"],))
    return cur.fetchall()


@app.route("/all-users")
def all_users():
    cur = g.db.cursor()
    cur.execute("SELECT id, name FROM users")
    return cur.fetchall()
