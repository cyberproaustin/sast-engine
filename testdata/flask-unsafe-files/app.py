import os
import tempfile

from flask import Flask, request

app = Flask(__name__)

GREETING = "Hello, {}!"


@app.route("/report")
def report():
    # POSITIVE. mktemp hands back a name without creating anything, so another process
    # can put its own file -- or a symlink -- there first.
    path = tempfile.mktemp()
    with open(path, "w") as fh:
        fh.write("report")
    # POSITIVE. The world-writable bit is what makes this wrong, not the number.
    os.chmod(path, 0o777)
    return path


def become_root():
    # POSITIVE. A process running as root does everything as root, so any defect anywhere
    # in it is a defect with the whole machine behind it.
    os.setuid(0)


def drop_privileges():
    # NEGATIVE. Dropping TO an unprivileged account is the point of the call.
    os.setuid(1000)


@app.route("/report-safe")
def report_safe():
    # NEGATIVE. mkstemp creates the file and returns a handle to it, and the mode grants
    # nothing to others.
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.chmod(path, 0o600)
    return path


@app.route("/greet")
def greet():
    # NEGATIVE. The caller's data is an ARGUMENT to a format the application wrote.
    return GREETING.format(request.args.get("name", "world"))


@app.route("/greet-caller")
def greet_caller():
    # POSITIVE. The caller wrote the FORMAT. Python's format language walks attributes,
    # so `{0.__class__.__init__.__globals__}` reaches module globals from here.
    template = request.args["template"]
    return template.format(app)
