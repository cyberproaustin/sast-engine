import os
import random
import secrets
import time
import uuid

from flask import Flask, make_response, send_from_directory

app = Flask(__name__)


@app.route("/session")
def session():
    # POSITIVE. A version 1 UUID is the clock and a MAC address written down. It looks
    # exactly like a version 4 one and is not a secret at all.
    response = make_response("ok")
    response.set_cookie("session", str(uuid.uuid1()), httponly=True, secure=True, samesite="Lax")
    return response


@app.route("/deal")
def deal():
    # POSITIVE. Seeded from the clock, every number that follows is recomputable by
    # anyone who knows roughly when the process reached this line.
    random.seed(time.time())
    return str(random.random())


@app.route("/nonce")
def nonce():
    # POSITIVE. token_hex counts BYTES, not characters, so this is sixty-four bits -- and
    # the cookie is what makes sixty-four bits too few.
    response = make_response("ok")
    response.set_cookie("sid", secrets.token_hex(8), httponly=True, secure=True, samesite="Lax")
    return response


@app.route("/tempname")
def tempname():
    # NEGATIVE. The identical call where the only requirement is uniqueness.
    return "upload-" + secrets.token_hex(8) + ".bin"


@app.route("/token")
def token():
    # NEGATIVE. Thirty-two bytes.
    return secrets.token_urlsafe(32)


@app.route("/uptime")
def uptime():
    # NEGATIVE. The clock reported as the clock.
    return str(time.time() - os.getpid())


@app.route("/files/<name>")
def files(name):
    # POSITIVE. The filesystem root served whole.
    return send_from_directory("/", name)
