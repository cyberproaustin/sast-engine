import os
import random
import secrets
import time
import uuid

from flask import Flask, make_response, send_from_directory

app = Flask(__name__)


@app.route("/session")
def session():
    # POSITIVE. A version 1 UUID is a timestamp and a node identifier written down. The
    # version nibble says which kind it is if anybody looks, and nobody does: it is the
    # same length and the same shape as a random one, and it is not a secret at all.
    response = make_response("ok")
    response.set_cookie("session", str(uuid.uuid1()), httponly=True, secure=True, samesite="Lax")
    return response


@app.route("/deal")
def deal():
    # POSITIVE. Seeded from the clock, every number that follows is recomputable by
    # anyone who knows roughly when the process reached this line -- including the one
    # handed back here as a claim code.
    random.seed(time.time())
    return str(random.randint(100000, 999999))


@app.route("/nonce")
def nonce():
    # POSITIVE. token_hex counts BYTES, not characters, so this is thirty-two bits -- four
    # billion candidates, and the cookie is what makes that too few. The threshold this
    # rule uses is 128 bits, which is what a session identifier is normally held to;
    # sixty-four is sometimes cited as a floor and is not what anybody recommends.
    response = make_response("ok")
    response.set_cookie("sid", secrets.token_hex(4), httponly=True, secure=True, samesite="Lax")
    return response


@app.route("/tempname")
def tempname():
    # NEGATIVE. The identical call where the only requirement is uniqueness.
    return "upload-" + secrets.token_hex(4) + ".bin"


@app.route("/token")
def token():
    # NEGATIVE. Thirty-two bytes.
    return secrets.token_urlsafe(32)


@app.route("/started")
def started():
    # NEGATIVE. The clock and the process id reported as themselves, which is what both
    # are for. The classification is at the source and the judgement is at the sink, so
    # ordinary uses of either are not findings anywhere.
    return f"{time.time()} pid={os.getpid()}"


@app.route("/files/<name>")
def files(name):
    # POSITIVE. The filesystem root served whole.
    return send_from_directory("/", name)
