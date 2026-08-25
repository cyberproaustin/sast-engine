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
    # NEGATIVE for THIS rule: the expansion limits are left in place. Nothing here says
    # the parser is safe overall -- what a supplied parser does depends on how it was
    # built, and the engine cannot see that, which is why the entity rule below stays
    # quiet about every call that supplies one.
    parser = etree.XMLParser(resolve_entities=False)
    return str(etree.fromstring(request.data, parser))


@app.route("/import-default", methods=["POST"])
def import_default():
    # POSITIVE, and a DIFFERENT weakness: no parser at all, so lxml's default is used.
    # That parser expands internal entities, and before lxml 5 it resolved external ones
    # too. Supplying a parser is where the fix goes, and the engine cannot see how a
    # supplied one was configured -- so it says nothing about those rather than reporting
    # what may be the remedy. That is a stated miss, not a claim that they are safe.
    return str(etree.fromstring(request.data))
