"""One shape, two roles, and only the use tells them apart.

Every provider-issued value in this file looks the same from the outside: a run of
characters in a format its issuer defined. A rule that matched the SHAPE reported all of
them, and measured across ten production repositories that rule produced 27 false
findings in a single program -- Firebase web API keys, a Google Drive playback key, Adobe
Primetime client attestations -- because it never asked WHOSE credential the value was.

The question is whether THIS program relies on the value being secret.

A value the program hands outward to say which client it is is the third party's public
configuration. yt-dlp is a client of every site it has an extractor for and there is no
server in it whose door any of those keys opens. A value the program configures itself
with, dials its own database with, or admits a caller by is a secret, and so is a value
it presents as its own credential -- and the request part it travels under is where the
program says which of the two it is. `Authorization` is a program proving who it is;
`key` and `client_id` are a program saying which client it is.

Nothing here turns on the vendor. Two of the negatives and one of the positives are the
same `AIza`/`sk_live_`/`eyJ` family of shapes on opposite sides of the judgement, which
is the point: a rule keyed on the prefix would get every one of them wrong in one
direction or the other.
"""
import requests
from flask import Flask, request

app = Flask(__name__)

# POSITIVE. A signing key written into this program's OWN configuration. No request is
# involved and no third party: the program configures itself with it, so anybody holding
# the repository can mint a session for anybody.
app.config["SECRET_KEY"] = "s3cr3t-dev-key"

# POSITIVE. The database this program dials and the password it dials with. There is no
# third party here at all -- this program is the client and the server is its own, and
# the password is in every clone of the repository.
DATABASE_URL = "postgres://app_user:hunter2@db.internal:5432/production"

# POSITIVE. The same provider-issued shape as the negatives below, and it is reported,
# because of where the program puts it: an Authorization header is this program proving
# who it is, and Stripe bills whoever presents it. Nothing about the VALUE says that --
# the option name does, and that is the only place the program says it.
STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"

# NEGATIVE. A Firebase browser key. Google publishes it in the web client of every
# application that uses Identity Toolkit: it names a project and does not authenticate
# whoever holds it. The user's own credential is the email and password in the request
# body, which this program never writes down.
FIREBASE_WEB_KEY = "AIzaSyD-1234567890abcdefghijklmnopqrstu"


@app.route("/session", methods=["POST"])
def session():
    # POSITIVE, and the use with no request in it at all. The comparison IS the
    # authentication: the value that decides whether this caller is let in is in every
    # clone of the repository and stays in its history after it is changed, so nobody
    # can revoke it without shipping a release.
    if request.form["password"] == "F12Zr47jyX@HjmM":
        return "welcome"
    return "no", 403


@app.route("/charges")
def charges():
    # POSITIVE, reported at the constant above. The key travels outward exactly as the
    # negatives do -- same kind of call, same kind of service -- and the program files it
    # under Authorization, which is the request part reserved for saying who you are.
    reply = requests.get(
        "https://api.stripe.com/v1/charges",
        headers={"Authorization": f"Bearer {STRIPE_KEY}"})
    return reply.text


@app.route("/thumbnail")
def thumbnail():
    # NEGATIVE. The key is a query PARAMETER of somebody else's API, sent beside the
    # Referer that service's own web client sends -- and a Referer is public by
    # construction. This is googledrive.py:143 with the names changed.
    reply = requests.get(
        "https://content-workspacevideo-pa.googleapis.com/v1/drive/media/playback",
        params={"key": "AIzaSyC-abcdefghijklmnopqrstuvwxyz01234"},
        headers={"Referer": "https://drive.google.com/"})
    return reply.text


@app.route("/enrol")
def enrol():
    # NEGATIVE. The browser client key built straight into the request line, which is how
    # cybrary.py:12 uses it: the constant is three lines away from the URL it belongs to
    # and the engine has to follow the name to see the role.
    reply = requests.get(
        f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_WEB_KEY}")
    return reply.text


@app.route("/register")
def register():
    # NEGATIVE. A public client identifier posted to an OAuth token endpoint, which is
    # what an Adobe Primetime software statement is: every copy of every client ships the
    # same one, and the service exchanges it for a real client credential it then keeps.
    # It is filed under `client_id` in the same request body as `client_secret` would be,
    # and the difference between those two names is the whole judgement.
    reply = requests.post(
        "https://sp.auth.example.com/o/client/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIwNjg5ZmU2MyJ9.WFhYWFhYWFhYWFhYWFhYWFhY",
        })
    return reply.text
