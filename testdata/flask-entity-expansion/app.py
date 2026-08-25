from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_document():
    # POSITIVE. huge_tree removes the guard that stops a small document expanding into a
    # large one, which is the whole of the attack: a few kilobytes becomes gigabytes and
    # the process dies holding whatever else it was doing.
    parser = etree.XMLParser(huge_tree=True)
    return str(etree.fromstring(request.data, parser))


@app.route("/import-guarded", methods=["POST"])
def import_guarded():
    # NEGATIVE. The default limits are left in place. That this parser still resolves
    # entities is a different weakness with its own number, and the line below reports
    # under it rather than this one.
    parser = etree.XMLParser(resolve_entities=False)
    return str(etree.fromstring(request.data, parser))


@app.route("/import-default", methods=["POST"])
def import_default():
    # POSITIVE, and a DIFFERENT weakness: no parser at all, so lxml's default is used and
    # that one resolves external entities. Supplying a parser is how this gets fixed,
    # which is why the two routes above are silent about it -- a rule that reports its own
    # remedy is worse than one that stays quiet.
    return str(etree.fromstring(request.data))
