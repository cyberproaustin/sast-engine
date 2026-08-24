import os
import uuid

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_DIR = "/srv/uploads"


@app.route("/upload", methods=["POST"])
def upload():
    # POSITIVE. secure_filename ends traversal and preserves the extension, so the
    # caller still decides what kind of file the server now holds.
    f = request.files["file"]
    name = secure_filename(f.filename)
    f.save(os.path.join(UPLOAD_DIR, name))
    return "ok"


@app.route("/upload-raw", methods=["POST"])
def upload_raw():
    # POSITIVE. No transform at all.
    f = request.files["file"]
    f.save(os.path.join(UPLOAD_DIR, f.filename))
    return "ok"


@app.route("/upload-generated", methods=["POST"])
def upload_generated():
    # NEGATIVE. The stored name is generated, so nothing the caller sent decides the
    # extension. No untrusted data reaches the destination.
    f = request.files["file"]
    dest = os.path.join(UPLOAD_DIR, str(uuid.uuid4()) + ".png")
    f.save(dest)
    return "ok"


@app.route("/note", methods=["POST"])
def note():
    # NEGATIVE. `.save()` on a record, not on an upload. This is the shape that made
    # matching by method name alone unusable.
    body = request.json
    record = Note(body["title"])
    record.save()
    return "ok"


class Note:
    def __init__(self, title):
        self.title = title

    def save(self):
        return self.title
