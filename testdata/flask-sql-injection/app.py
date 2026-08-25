"""The same two SQL channels, on a second language, with no engine or policy change.

`cursor.execute(sql, params)` is the canonical parameterized call and the canonical
injection, depending only on which argument the caller's data ends up in. The channel
that finds the JavaScript case finds this one, because what it describes is the
operation rather than the library.
"""
import mailer

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


@app.route("/user-fstring")
def find_user_fstring():
    # The same injection written as an f-string, which is how most Python composes a
    # statement now. The STATIC text of an f-string is a value too, and lowering only its
    # interpolations lost the half the program wrote -- so a rule asking whether a composed
    # value contains a SQL verb could answer for `"SELECT ..." % x` and not for this.
    cur = g.db.cursor()
    cur.execute(f"SELECT id, name FROM users WHERE login = '{request.args['login']}'")
    return cur.fetchall()


@app.route("/greeting")
def greeting():
    # NEGATIVE, and what the SQL verb buys. A method called `execute` on something that is
    # not a database is ordinary English: nodebb composes `${user}@${domain}` and hands it
    # to a WebFinger lookup called `query`, and it read as an injection. A statement says
    # what it does, and this one says nothing.
    return mailer.execute(f"welcome back, {request.args['name']}")
