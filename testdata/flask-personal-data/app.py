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
    # NEGATIVE. An email address is personal but it is also reissuable and is the key
    # every application already logs; the list is deliberately short.
    log.info("enrolling %s", request.form["email"])
    user = USERS.setdefault(request.form["email"], {})
    user["is_admin"] = False
    return "ok"
