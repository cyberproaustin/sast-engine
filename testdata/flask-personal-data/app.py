import logging

import requests
from flask import Flask, request

app = Flask(__name__)
log = logging.getLogger(__name__)
USERS = {}


@app.route("/enroll", methods=["POST"])
def enroll():
    # POSITIVE. Neither of these can be reissued after it leaks.
    log.info("enrolling %s", request.form["ssn"])
    requests.post("https://analytics.example.com/events", data=request.form["date_of_birth"])

    # POSITIVE. The caller decides what this account may do.
    user = USERS.setdefault(request.form["email"], {})
    user["is_admin"] = request.form["is_admin"]
    return "ok"


@app.route("/enroll-safe", methods=["POST"])
def enroll_safe():
    # NEGATIVE, and a STATED MISS rather than a safe line. An email address IS personal
    # data and logging one is a disclosure. It is off this list because it is the key
    # every application already logs and because it can be changed, and a list that
    # matched it would report the identifier every request is traced by. The list is short
    # for that reason and this is what the shortness costs.
    log.info("enrolling %s", request.form["email"])
    user = USERS.setdefault(request.form["email"], {})
    user["is_admin"] = False
    return "ok"
