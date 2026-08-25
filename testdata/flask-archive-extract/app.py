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
