"""The same weakness in the language where the caller's key is not a property read.

Nothing in this file spells `request.something.id`. A Flask or Django route binds its
segments to ARGUMENTS -- `/records/<record_id>` arrives as `record_id` -- so an analysis
that only recognises a property read off a request object is silent on every handler
Python ever wrote, and this corpus is what says otherwise.

The parameter counts as a key because the registered ROUTE PATH interpolates its name.
That is the anchor, not the spelling: frameworks inject plenty of arguments whose names
end in `id`, and only the ones the path names came from the caller.
"""

from flask import Flask, jsonify

from context import get_authenticated_context

app = Flask(__name__)


# EXPECTED FINDING. The check admits any tenant administrator and says nothing about
# which record; the read then goes through the repository built with the server's own
# authority, keyed by the segment the caller chose. An administrator of any tenant reaches
# a record in any other.
@app.route("/records/<record_id>/rotate", methods=["POST"])
def rotate(record_id):
    ctx = get_authenticated_context()
    if not ctx.repo.is_tenant_admin():
        return jsonify({"error": "forbidden"}), 403
    record = ctx.system_repo.read_record("Client", record_id)
    ctx.system_repo.update_record(record)
    return jsonify({"ok": True})


# EXPECTED CLEAN, and this is the fix. The record is fetched through the very repository
# the check was about, so it cannot be one the caller's tenant does not hold; the elevated
# repository then writes it.
@app.route("/records/<record_id>/retire", methods=["POST"])
def retire(record_id):
    ctx = get_authenticated_context()
    if not ctx.repo.is_tenant_admin():
        return jsonify({"error": "forbidden"}), 403
    record = ctx.repo.read_record("Client", record_id)
    ctx.system_repo.update_record(record)
    return jsonify({"ok": True})


# EXPECTED CLEAN. Asked and acted through the same accessor. There is no second authority
# here and nothing to relate.
@app.route("/records/<record_id>/touch", methods=["POST"])
def touch(record_id):
    ctx = get_authenticated_context()
    if not ctx.repo.is_tenant_admin():
        return jsonify({"error": "forbidden"}), 403
    ctx.repo.update_record({"id": record_id})
    return jsonify({"ok": True})


# EXPECTED CLEAN. The selection carries the caller's own tenant, so it cannot reach a
# record outside it however the caller spells the segment.
@app.route("/records/<record_id>/rename", methods=["POST"])
def rename(record_id):
    ctx = get_authenticated_context()
    if not ctx.repo.is_tenant_admin():
        return jsonify({"error": "forbidden"}), 403
    record = ctx.system_repo.read_record("Client", record_id, ctx.tenant)
    ctx.system_repo.update_record(record)
    return jsonify({"ok": True})


# EXPECTED CLEAN, and this is what the name list is for. `cache.has()` is a guard, it sits
# on a sibling accessor of the same context, and the handler leaves from it -- identical
# in every way except that the question is not an authorization.
@app.route("/records/<record_id>/warm", methods=["POST"])
def warm(record_id):
    ctx = get_authenticated_context()
    if not ctx.cache.has(record_id):
        return jsonify({"error": "not found"}), 404
    ctx.system_repo.update_record({"id": record_id})
    return jsonify({"ok": True})
