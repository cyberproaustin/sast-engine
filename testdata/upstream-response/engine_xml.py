"""The same hook, a second syntax.

Eight of searxng's engine modules are this line, one per upstream that speaks XML, and
the pairing it makes is one this model already asserts for a document a CALLER sent:
lxml's default parser expands entities and this call supplies no parser of its own. A
parser does not care who wrote the document it was handed.
"""
from lxml import etree

categories = ["science"]


def request(query, params):
    params["url"] = "https://feeds.example.com/atom?q=" + query
    return params


def response(resp):
    # EXPECTED FINDING: an upstream's XML through a parser that expands entities.
    dom = etree.fromstring(resp.content)
    return [{"title": node.text} for node in dom]
