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
    # NEGATIVE. compare_digest does not leak how much of the guess was right, and it is a
    # call rather than a comparison, so there is nothing here for a rule about comparisons
    # to match. It is not magic: it can still reveal a length, which is why it is used on
    # digests, where the length is fixed and public.
    expected = hmac.new(b"secret", request.data, "sha256").hexdigest()
    if hmac.compare_digest(request.headers["Authorization"], expected):
        return "ok"
    return "bad signature", 401
