import hashlib

from flask import Flask, request

app = Flask(__name__)
PEPPER = "site-wide"


@app.route("/register", methods=["POST"])
def register():
    # POSITIVE. sha256 takes the data and nothing else, so the digest is a pure function
    # of the password: one precomputed table works against every account that chose it.
    digest = hashlib.sha256(request.form["password"].encode()).hexdigest()
    return digest


@app.route("/register-salted", methods=["POST"])
def register_salted():
    # NEGATIVE. The password is composed with something else before it is hashed, and
    # something else is what a salt is. Whether THIS salt is a good one is a different
    # question with its own number (CWE-760), and this rule does not answer it.
    salted = PEPPER + request.form["password"]
    return hashlib.sha256(salted.encode()).hexdigest()


@app.route("/register-kdf", methods=["POST"])
def register_kdf():
    # NEGATIVE. A key derivation function takes the salt as an argument, so there is
    # somewhere for it to go and it went there.
    return hashlib.pbkdf2_hmac(
        "sha256", request.form["password"].encode(), request.form["nonce"].encode(), 600000
    ).hex()


@app.route("/etag")
def etag():
    # NEGATIVE. Not a password. The classification is what makes this rule narrow: a
    # digest of ordinary request data is how caches are keyed and is not a defect.
    return hashlib.sha256(request.args["path"].encode()).hexdigest()
