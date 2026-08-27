"""A response is text somebody else wrote.

Every value here arrives from a service on the other end of a network call, and the
program treats each one differently. What separates the findings from the silence is the
DESTINATION: a response that is interpreted is dangerous whoever runs the service that
sent it, and a response that is logged or handed onward is an integration.

The last handler is the other direction of the same call, and it is here so the two
judgements can be read together: the key this program presents to the upstream is that
upstream's public configuration and not this program's secret, which is what the client
role rule already decides. Nothing about seeding the ANSWER changes what the REQUEST said.
"""
import logging
import os

import requests
from flask import Flask, g, request

app = Flask(__name__)

# The upstream publishes this in its own web client. Presented outward, under a request
# part that names which client is calling rather than proving who it is.
CATALOG_KEY = "AIzaSyD8xK2mPqR7vN4wL9jH3sT6yU1bC5dF0gE"

# The same provider, the same shape, and this one IS this program's credential: it goes
# out in the request part reserved for proving who is calling.
CATALOG_SECRET = "sk_live_51H8xQ2eZvKYlo2C0Dj4TgHqW"

log = logging.getLogger(__name__)


@app.route("/import")
def import_catalog():
    body = requests.get("https://catalog.example.com/v1/items").json()
    # EXPECTED FINDING: the catalog service chose this string and it is run by a shell.
    os.system("convert " + body["thumbnail"] + " /var/cache/thumb.png")
    return "ok"


@app.route("/sync")
def sync_catalog():
    body = requests.get("https://catalog.example.com/v1/items").json()
    cur = g.db.cursor()
    # EXPECTED FINDING: interpolated into a statement.
    cur.execute("INSERT INTO items (sku) VALUES ('" + body["sku"] + "')")
    return "ok"


@app.route("/audit")
def audit_catalog():
    body = requests.get("https://catalog.example.com/v1/items").json()
    # NO FINDING: a log of what the upstream said is a log of what the upstream said.
    log.info("catalog returned %s", body["sku"])
    return "ok"


@app.route("/mirror")
def mirror_catalog():
    body = requests.get("https://catalog.example.com/v1/items").json()
    # NO FINDING: passing one service's answer to another service is an integration.
    requests.post("https://mirror.example.com/v1/items", json={"sku": body["sku"]})
    return "ok"


@app.route("/lookup")
def lookup_item():
    # NO FINDING: the key travels outward under a request part that says WHICH CLIENT is
    # calling, so it is the catalog's public configuration rather than this program's
    # credential. Seeding the response as untrusted says nothing about the request.
    resp = requests.get(
        "https://catalog.example.com/v1/lookup",
        params={"key": CATALOG_KEY, "sku": request.args["sku"]},
    )
    return resp.text


@app.route("/private")
def private_lookup():
    # EXPECTED FINDING at the line CATALOG_SECRET is written. The same provider-issued
    # shape as CATALOG_KEY and the opposite judgement, so that this corpus proves the
    # client-role rule is ENGAGED rather than merely quiet. What separates the two is the
    # request part the program files the value under, and seeding the answer changed
    # neither reading.
    resp = requests.get(
        "https://catalog.example.com/v1/private",
        headers={"Authorization": f"Bearer {CATALOG_SECRET}"},
    )
    return resp.text
