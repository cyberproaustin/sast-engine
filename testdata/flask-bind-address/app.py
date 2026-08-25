import os

from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "ok"


def serve_everywhere():
    # POSITIVE. The listener accepts connections on every address the host has. On a
    # laptop that is a demo; on a host with a second interface, a container in
    # host-network mode, or a cloud instance with a public address, it is the difference
    # between a service the application can reach and a service anybody can.
    app.run(host="0.0.0.0", port=8000)


def serve_locally():
    # NEGATIVE. One address, and the loopback one.
    app.run(host="127.0.0.1", port=8000)


def serve_configured():
    # NEGATIVE, and the correct way to do it: the address is a deployment decision, so it
    # is read from the environment and is not a literal. A rule about a written address
    # says nothing here, which is the honest answer rather than a lucky one.
    app.run(host=os.environ["BIND_HOST"], port=8000)
