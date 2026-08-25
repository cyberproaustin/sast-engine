import csv
import io

from flask import Flask, request

app = Flask(__name__)


@app.route("/export")
def export():
    # POSITIVE. A spreadsheet does not treat a cell beginning `=`, `+`, `-` or `@` as
    # text: whoever opens this export runs it, on their machine, with their access.
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["name", request.args["name"]])
    return buf.getvalue()


@app.route("/export-fixed")
def export_fixed():
    # NEGATIVE. Nothing the caller sent reaches the file.
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["name", "example"])
    return buf.getvalue()
