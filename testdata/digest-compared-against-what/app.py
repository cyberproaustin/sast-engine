"""Five weak digests, five equality tests, and what is on the OTHER SIDE decides.

`weak-hash-by-use` proved that the algorithm's name is not the judgement and that the use
is. This corpus is the next question down: the use here is an equality test in all five
cases, written the same way each time, and only two of them are the weakness the operator
appears to state.

Measured across ten production repositories, the rule that read the operator alone
produced four findings and an independent reader judged every one of them not worth
reporting. Three of them are the negatives below, taken shape for shape:

  medplum   a Lua script's SHA-1 addresses Redis's script cache, and the NUMERIC reply is
            tested for 1. The classification rode through the unresolved call into a value
            that is not a digest and never was.
  linkding  a preview file is named after the MD5 of its URL and the NAME is compared with
            the one on the record. A filename that contains a digest is a filename.
  the cache the digest names a slot and nothing is decided by the answer, which is the
            case `weak-hash-by-use` already holds and the one this rule must never take.

The fourth was mitmproxy's htpasswd verifier, and it is the reason this corpus exists at
all: there IS a weakness on that line and the collision rule was naming the wrong one. A
SHA-1 collision does not produce a second password for a digest somebody else chose. What
is wrong is the construction -- one unsalted pass of a function built to be fast -- and
that is a different number, so the line is reported and reported differently.
"""
import base64
import hashlib

from flask import Flask, request

app = Flask(__name__)

# The digest of the release this build was cut from, recorded when it was published.
RECORDED_DIGEST = "d41d8cd98f00b204e9800998ecf8427e"
_LINK_SECRET = "signing-secret-from-the-vault"

CACHE = {}
ACCOUNTS = {}


@app.route("/download")
def download():
    # POSITIVE. The equality test IS the authorisation: whoever presents a signature
    # matching this digest is served the document, and the program has no other evidence.
    # Anybody who can produce a second input with the same digest is served it too, which
    # is the one property MD5 no longer has.
    doc = request.args["doc"]
    expected = hashlib.md5(f"{doc}{_LINK_SECRET}".encode()).hexdigest()
    if expected == request.args["sig"]:
        return f"here is {doc}"
    return "no", 403


@app.route("/artifact")
def artifact():
    # POSITIVE, and the plainest form: a computed digest against one recorded in the
    # source. The recorded side is written down AS a digest, which is what separates it
    # from the numeric reply below -- both are literals and only one of them is evidence
    # that digests are what this comparison is about.
    computed = hashlib.md5(_release_bytes()).hexdigest()
    if computed != RECORDED_DIGEST:
        return "corrupt", 409
    return "ok"


@app.route("/login", methods=["POST"])
def login():
    # POSITIVE, under a different number, and the whole reason this corpus is not simply
    # a narrowing. mitmproxy verifies an Apache `{SHA}` htpasswd entry exactly like this:
    # the submitted password is hashed and compared with the stored digest, past the
    # five-character prefix that says which format the entry is in.
    #
    # Collision resistance is not what fails. Finding two inputs that hash alike does not
    # give anybody a password for a digest they did not choose, and reporting a collision
    # bypass here would be telling the reader something untrue about a line that is
    # nevertheless wrong. What is wrong is that the stored value is a single unsalted pass
    # of a fast function: the common passwords come out of a table and the rest come out
    # of a GPU.
    pwhash = ACCOUNTS.get(request.form["user"], "")
    digest = hashlib.sha1(request.form["password"].encode()).digest()
    expected = base64.b64encode(digest).decode("ascii")
    if pwhash[5:] == expected:
        return "welcome"
    return "no", 403


@app.route("/context", methods=["POST"])
def context():
    # NEGATIVE. medplum's shape. The SHA-1 is how Redis's script cache is ADDRESSED --
    # the digest is the script's name and the server computes the same one -- and what
    # comes back is the script's numeric result. The class follows the digest into a call
    # the frontend cannot resolve and out the other side, and `== 1` is not a comparison
    # of digests however it got there.
    script_sha = hashlib.sha1(_COMPARE_AND_SET.encode()).hexdigest()
    replaced = _evalsha(script_sha, request.form["topic"], request.form["version"])
    if replaced == 1:
        return "replaced"
    return "stale", 409


@app.route("/preview")
def preview():
    # NEGATIVE. linkding's shape. The digest names the file the preview was saved as, and
    # the comparison asks whether the preview has changed since the row was written. What
    # is compared is not the digest: it is a filename the digest was built into, and a
    # collision costs a stale thumbnail.
    url = request.args["url"]
    new_file = f"{hashlib.md5(url.encode()).hexdigest()}.png"
    if new_file != _stored_preview(url):
        return "changed"
    return "same"


@app.route("/report")
def report():
    # NEGATIVE, and the contrast the whole judgement rests on: the identical call, the
    # identical algorithm, and the digest is a LABEL. It names a cache slot. A collision
    # returns the wrong report to whoever asked second, which is a bug about correctness
    # and not a statement about who anybody is -- and character for character this is how
    # every memoised handler in the corpus is written.
    key = "report:" + hashlib.md5(request.args["q"].encode()).hexdigest()
    hit = CACHE.get(key)
    if hit is not None:
        return hit
    CACHE[key] = "computed"
    return "computed"


_COMPARE_AND_SET = "redis.call('SET', KEYS[1], ARGV[1]) return 1"


def _release_bytes():
    with open("/srv/releases/current.tar", "rb") as fh:
        return fh.read()


def _evalsha(sha, topic, version):
    """Stands in for the Redis client this program would hold."""
    return 1


def _stored_preview(url):
    """Stands in for the row the preview filename was written to."""
    return ""
