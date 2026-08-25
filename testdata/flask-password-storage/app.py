import base64

from cryptography.fernet import Fernet
from flask import Flask, request

app = Flask(__name__)
CIPHER = Fernet(Fernet.generate_key())


@app.route("/store-encoded", methods=["POST"])
def store_encoded():
    # POSITIVE. Encoding is not hiding: base64 turns straight back into what went in, so
    # whoever holds the result holds the password.
    stored = base64.b64encode(request.form["password"].encode())
    return str(stored)


@app.route("/store-encrypted", methods=["POST"])
def store_encrypted():
    # POSITIVE, and a different weakness. Encryption is not hashing -- it is recoverable
    # by design, which is exactly what a stored password must never be.
    stored = CIPHER.encrypt(request.form["password"].encode())
    return str(stored)


@app.route("/store-hashed", methods=["POST"])
def store_hashed():
    # NEGATIVE. A hash is one-way, so what is stored is a verifier rather than the
    # password, and nothing that reads it can recover what was hashed.
    from werkzeug.security import generate_password_hash

    return generate_password_hash(request.form["password"])
