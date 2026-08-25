import ldap
from flask import Flask, request
from lxml import etree

app = Flask(__name__)
DIRECTORY = ldap.initialize("ldap://directory.internal")
DOC = etree.parse("people.xml")


@app.route("/find")
def find():
    # POSITIVE. A `*` where the name goes turns "this user with this password" into
    # "any user".
    name = request.args["name"]
    return str(DIRECTORY.search_s("dc=example", ldap.SCOPE_SUBTREE, "(uid=%s)" % name))


@app.route("/find-bound")
def find_bound():
    # NEGATIVE. The caller's value is what is being searched FOR, not part of the filter
    # the application wrote.
    return str(DIRECTORY.search_s("dc=example", ldap.SCOPE_SUBTREE, request.args["name"]))


@app.route("/lookup")
def lookup():
    # POSITIVE. The caller writes the expression, so the caller picks the nodes --
    # including the ones holding everybody else's records.
    name = request.args["name"]
    return str(DOC.xpath("//person[name='" + name + "']"))


@app.route("/lookup-fixed")
def lookup_fixed():
    # NEGATIVE. A fixed expression.
    return str(DOC.xpath("//person"))
