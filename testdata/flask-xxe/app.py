from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_xml():
    # POSITIVE. lxml's DEFAULT parser resolves entities, so here the absence of
    # configuration is the configuration.
    doc = etree.fromstring(request.data)
    return str(len(doc))


@app.route("/import-fixed", methods=["POST"])
def import_fixed():
    # NEGATIVE. Nothing the caller sent reaches the parser.
    doc = etree.fromstring(b"<root/>")
    return str(len(doc))
