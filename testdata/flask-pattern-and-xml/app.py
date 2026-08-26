"""Two small languages a caller must not be allowed to write.

Neither is a path and neither is a protocol. A glob PATTERN chooses which files a program
walks rather than which file it opens, and text built into an XML document is the caller
writing syntax -- which is the same evidence SQL injection rests on, at a different
interpreter.
"""
import glob
from xml.etree import ElementTree
from xml.sax import saxutils

from flask import Flask, request

app = Flask(__name__)


@app.route("/files")
def files():
    # POSITIVE. `**/*` walks the whole tree from wherever the program started, and a
    # character class reads names the caller was never offered.
    return str(glob.glob("/srv/data/" + request.args["pattern"]))


@app.route("/files-escaped")
def files_escaped():
    # NEGATIVE, and the language ships the proof: escaping the wildcards leaves a name.
    return str(glob.glob("/srv/data/" + glob.escape(request.args["pattern"])))


@app.route("/note", methods=["POST"])
def note():
    # POSITIVE. Built INTO the document rather than carried by it, so a caller who writes
    # a tag gets a tag.
    doc = "<note><body>" + request.form["body"] + "</body></note>"
    return str(ElementTree.fromstring(doc))


@app.route("/note-escaped", methods=["POST"])
def note_escaped():
    # NEGATIVE. The characters that would start a tag are replaced first.
    doc = "<note><body>" + saxutils.escape(request.form["body"]) + "</body></note>"
    return str(ElementTree.fromstring(doc))


@app.route("/note-whole", methods=["POST"])
def note_whole():
    # NEGATIVE for THIS judgement: a document the caller SENT is a different question,
    # judged by what the parser was asked to resolve, and reported under its own number.
    return str(ElementTree.fromstring(request.form["doc"]))
