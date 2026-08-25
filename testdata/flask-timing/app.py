import hmac

from flask import Flask, request

app = Flask(__name__)


@app.route("/webhook", methods=["POST"])
def webhook():
    # POSITIVE. The same weakness on the second language. The header is named
    # `Authorization` rather than `X-Signature` because a name is the only evidence the
    # engine has that a header carries a credential -- which is a stated miss on every
    # signature header an application chose to name something else.
    expected = hmac.new(b"secret", request.data, "sha256").hexdigest()
    if request.headers["Authorization"] == expected:
        return "ok"
    return "bad signature", 401


@app.route("/webhook-safe", methods=["POST"])
def webhook_safe():
    # NEGATIVE. compare_digest takes the same time whatever the inputs are, and it is a
    # call rather than a comparison.
    expected = hmac.new(b"secret", request.data, "sha256").hexdigest()
    if hmac.compare_digest(request.headers["Authorization"], expected):
        return "ok"
    return "bad signature", 401
