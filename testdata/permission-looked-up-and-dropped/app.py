"""A control the program computes and then does nothing with.

Every rule that reads a missing authorization reads an ABSENCE: no gate here where there
is one beside it, no gate on this branch where the other branch has one, a gate that does
not stop what follows. This file holds the case where nothing is absent -- the lookup is
right, the mapping is the right mapping, the rejection is a real rejection and the branch
it sits on is obeyed -- and the permission it found is never asked for.

Four functions, one weakness. What separates them is the program's own words: what the
value came out of, what it was bound to, what the enclosing function calls itself, and
whether anything is ever done with the answer beyond asking whether the lookup succeeded.
"""

import flask

app = flask.Flask(__name__)

PRIVATE_META_PERMISSION_MAP = {
    "Order": "MANAGE_ORDERS",
    "Checkout": "MANAGE_CHECKOUTS",
}

PUBLIC_META_PERMISSION_MAP = {
    "Order": "READ_ORDERS",
}

FEATURE_FLAGS = {"Order": "beta"}


def granted(user, permission):
    return permission in getattr(user, "permissions", [])


def check_metadata_permission(user, type_name, private=False):
    """The weakness. The permission is selected and then only asked to exist.

    `if not meta_permission` is a question about the MAPPING -- did the lookup find an
    entry -- and it is the only question this function ever asks. Nobody consults the
    caller, and the function's own name says that is what it is for, so every request the
    surrounding gate admitted reaches the operation with this permission unasked.
    """
    if private:
        meta_permission = PRIVATE_META_PERMISSION_MAP.get(type_name)
    else:
        meta_permission = PUBLIC_META_PERMISSION_MAP.get(type_name)

    if not meta_permission:
        raise NotImplementedError("no permission for " + type_name)


def check_metadata_permission_applied(user, type_name, private=False):
    """The same function with the question asked. Silent, and one line is the difference.

    Same name, same mapping, same rejection. `granted(user, meta_permission)` is the whole
    of what the one above is missing, and it is what the rule looks for: the permission
    handed to something that could enforce it.
    """
    if private:
        meta_permission = PRIVATE_META_PERMISSION_MAP.get(type_name)
    else:
        meta_permission = PUBLIC_META_PERMISSION_MAP.get(type_name)

    if not meta_permission:
        raise NotImplementedError("no permission for " + type_name)
    if not granted(user, meta_permission):
        raise PermissionError("denied")


def get_metadata_permission(type_name):
    """A permission RETURNED as data. Silent because the question belongs to its caller.

    Identical to the weakness above in every respect but the one that decides: this
    function fetches, and its name says so. A rule that read the mapping and the binding
    without reading the enclosing function would report every permission resolver in every
    codebase.
    """
    meta_permission = PRIVATE_META_PERMISSION_MAP.get(type_name)
    if not meta_permission:
        raise NotImplementedError("no permission for " + type_name)
    return meta_permission


def check_type_is_released(type_name):
    """A value dropped the same way, and not a permission. Silent, and correctly so.

    The engine cannot know what a value is FOR. The only statements of intent a program
    contains are the names it chose, and nothing here is named for a permission -- so
    there is nothing to say about a flag that was looked up and not used.
    """
    flag = FEATURE_FLAGS.get(type_name)
    if not flag:
        raise NotImplementedError("unknown type " + type_name)


@app.route("/metadata/<type_name>", methods=["POST"])
def update_metadata(type_name):
    check_metadata_permission(flask.g.user, type_name, private=True)
    check_metadata_permission_applied(flask.g.user, type_name, private=True)
    check_type_is_released(type_name)
    get_metadata_permission(type_name)
    return flask.jsonify({"ok": True})
