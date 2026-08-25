import zipfile

from flask import Flask, request

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_extension():
    # POSITIVE. Every entry in an archive names its own destination, so an entry called
    # `../../etc/cron.d/x` writes there. The traversal is inside the file rather than in
    # the call, which is why the question is what the archive IS rather than what the
    # path says -- and the dataflow already knows, because the handle came out of
    # ZipFile() on something the caller sent.
    with zipfile.ZipFile(request.files["bundle"]) as archive:
        archive.extractall("/tmp/extensions")
    return "ok"


@app.route("/import-bundled", methods=["POST"])
def import_bundled():
    # NEGATIVE. The archive is one this application ships, so its entries are ones this
    # application wrote.
    with zipfile.ZipFile("/opt/app/bundle.zip") as archive:
        archive.extractall("/tmp/extensions")
    return "ok"


@app.route("/import-by-hand", methods=["POST"])
def import_by_hand():
    # POSITIVE, and the other half of the same weakness. A program that walks the entries
    # itself instead of calling extractall does the traversal by hand, one entry at a
    # time -- and it is the same finding, reached the same way: the loop variable carries
    # what the collection carried, and the collection came out of opening an archive the
    # caller sent.
    with zipfile.ZipFile(request.files["bundle"]) as archive:
        for name in archive.namelist():
            with open("/tmp/extensions/" + name, "wb") as out:
                out.write(archive.read(name))
    return "ok"


@app.route("/import-by-hand-bundled", methods=["POST"])
def import_by_hand_bundled():
    # NEGATIVE. The same loop over an archive this application ships. Nothing a caller
    # sent reaches it, so the entries are ones this application wrote.
    with zipfile.ZipFile("/opt/app/bundle.zip") as archive:
        for name in archive.namelist():
            with open("/tmp/extensions/" + name, "wb") as out:
                out.write(archive.read(name))
    return "ok"
