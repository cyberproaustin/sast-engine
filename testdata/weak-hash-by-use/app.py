"""One broken algorithm, six uses, and only the uses differ.

Every digest in this file comes from MD5 or SHA-1 and every one of them is written the
same way. A rule that matched the ALGORITHM reported all six; measured across ten
production repositories that rule produced 42 findings and an independent reader judged
39 of them worthless -- rate-limit bucket keys, a Wikimedia directory path, an ETag, and
twenty-six request signatures a remote site's own protocol demands.

What separates the three that matter from the three that do not is not in the call. It is
on the next line: whether the program ESTABLISHES something by the digest. A digest that
is compared, verified, or stored as the thing a login is checked against is standing in
for what it was computed from, and collision resistance is exactly what makes that
substitution sound. A digest that names a cache slot, a rate-limit bucket or a file is a
label, and a collision costs a cache miss.
"""
import hashlib
import hmac

from flask import Flask, request

from store import cache_path, set_password

app = Flask(__name__)

# The digest of the release this build was cut from, recorded when it was published.
RECORDED_DIGEST = "d41d8cd98f00b204e9800998ecf8427e"
_SIGNING_KEY = b"key-from-the-vault"


def _release_bytes():
    with open("/srv/releases/current.tar", "rb") as fh:
        return fh.read()


@app.route("/webhook", methods=["POST"])
def webhook():
    # POSITIVE. The digest is a signature and the program checks it: whoever produces a
    # second body with the same digest is accepted as the sender. `compare_digest` is
    # the careful way to write the comparison and it is still the moment the digest is
    # believed, so watching only the `==` operator would go quiet exactly where the
    # author took more care.
    expected = hashlib.md5(_SIGNING_KEY + request.get_data()).hexdigest()
    if not hmac.compare_digest(expected, request.headers.get("X-Signature", "")):
        return "bad signature", 403
    return "ok"


@app.route("/artifact")
def artifact():
    # POSITIVE. A computed digest against a recorded one, which is the plainest form of
    # the judgement: the check says the bytes are the bytes that were published, and an
    # algorithm anybody can find collisions in does not say that.
    computed = hashlib.md5(_release_bytes()).hexdigest()
    if computed != RECORDED_DIGEST:
        return "corrupt", 409
    return "ok"


@app.route("/account/password", methods=["POST"])
def change_password():
    # POSITIVE, and the one whose comparison is in another request entirely: the store
    # is what a later login is checked against, so the write says the whole thing on its
    # own. Reported at the assignment in store.py, where the digest lands.
    set_password(request.form["user"], request.form["password"])
    return "ok"


@app.route("/login", methods=["POST"])
def login():
    # NEGATIVE. healthchecks writes this five times and it was five findings. The digest
    # names a rate-limit bucket: two addresses that collided would share a counter, and
    # sharing a counter is not a security decision about either of them.
    email = request.form["email"]
    hashed = hashlib.sha1(email.encode()).hexdigest()
    if not authorize(f"em-{hashed}", 10, 3600):
        return "too many attempts", 429
    return "ok"


@app.route("/report")
def report():
    # NEGATIVE. A cache key. A collision returns the wrong report to whoever asked
    # second, which is a bug about correctness and not about who anybody is.
    key = "report:" + hashlib.md5(request.args["q"].encode()).hexdigest()
    hit = CACHE.get(key)
    if hit is not None:
        return hit
    CACHE[key] = "computed"
    return "computed"


@app.route("/thumbnail")
def thumbnail():
    # NEGATIVE. A filename, and the caller chose what goes into it -- which is what the
    # digest is FOR: the path is a fixed-length hex name whatever was asked for. Silent
    # about the algorithm, and silent about the path, because a hex digest cannot carry
    # a directory separator.
    return cache_path(request.args["url"])


@app.route("/avatar")
def avatar():
    # NEGATIVE. Gravatar's protocol is the MD5 of an address, so this call cannot be
    # anything else and changing it would break the feature. Nothing here is established
    # by the digest; it is a name somebody else's service answers to.
    email = request.args["email"].strip().lower()
    return "https://www.gravatar.com/avatar/" + hashlib.md5(email.encode()).hexdigest()


CACHE = {}


def authorize(key, capacity, refill_secs):
    """A token bucket, standing in for the one the corpus actually has."""
    tokens = CACHE.get(key, capacity)
    CACHE[key] = tokens - 1
    return tokens > 0
