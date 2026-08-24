from flask import Flask, jsonify, request

from helpers import run_ping

app = Flask(__name__)


@app.route("/ping")
def ping():
    # Flask binds the request to a module-level global rather than a handler
    # parameter. Same judgement, different plumbing.
    host = request.args.get("host")
    return run_ping(host)


@app.route("/orders/<order_id>")
def get_order(order_id):
    try:
        return jsonify(load_order(order_id))
    except Exception as err:
        return jsonify({"error": str(err)})


@app.route("/status")
def status():
    return run_ping("localhost")


def load_order(order_id):
    raise RuntimeError("driver: relation \"orders\" does not exist")
