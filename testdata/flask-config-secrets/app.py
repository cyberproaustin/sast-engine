import os

from flask import Flask

app = Flask(__name__)

# POSITIVE. A signing key written into the source is in every clone of the repository and
# stays in its history after somebody changes it -- and anybody holding the repository can
# mint a session.
app.config["SECRET_KEY"] = "s3cr3t-dev-key"

# POSITIVE. Matched by a WORD in the key rather than by its whole name: configuration keys
# are compound, and a list of the exact spellings somebody thought of is wrong at the first
# application that adds a suffix.
app.config["JWT_SECRET_KEY_V2"] = "am0r3C0mpl3xK3y"

# POSITIVE. The attribute form of the same decision, with a space in the key -- which is
# what Flask's own documentation puts there, so a value holding one is not disqualified.
app.secret_key = "F12Zr47j yX@H!jmM"

# NEGATIVE, and the correct way to write it: a key read from the environment is not a
# literal and never matches.
app.config["MAIL_PASSWORD"] = os.environ["MAIL_PASSWORD"]

# NEGATIVE. A double-submit CSRF token is not a secret in this sense -- the page has to
# echo it back -- and the key names a header rather than holding a key.
app.config["CSRF_TOKEN_HEADER"] = "X-CSRF-Token"

# NEGATIVE. Not a secret at all.
app.config["STATIC_FOLDER"] = "static"

# NEGATIVE. A settings schema explaining that a credential is required is a sentence, not
# a credential. Three words is the line between the two.
app.config["PASSWORD_HELP"] = "either password or private key is required"

# NEGATIVE. The endpoint a credential is sent TO is not the credential.
app.config["API_KEY_ENDPOINT"] = "https://example.test/oauth/access"

# NEGATIVE. The mask a value is replaced with before it is logged is the one literal a
# secret-named setting holds precisely BECAUSE the secret must not be there.
app.config["PASSWORD_MASK"] = "********"

# NEGATIVE. A key that is not set is not a key written down.
app.config["SESSION_SECRET"] = None
