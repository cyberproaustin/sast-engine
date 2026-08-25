import requests
from flask import Flask

app = Flask(__name__)


@app.route("/upstream")
def upstream():
    # POSITIVE. Certificate verification off.
    r = requests.get("https://api.example.com/status", verify=False)
    return r.text


@app.route("/upstream-strict")
def upstream_strict():
    # NEGATIVE.
    r = requests.get("https://api.example.com/status", timeout=5)
    return r.text


if __name__ == "__main__":
    # POSITIVE. The debug console executes Python sent to it.
    app.run(host="0.0.0.0", port=8080, debug=True)
