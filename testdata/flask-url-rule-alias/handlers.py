from flask import request


def report():
    # Reached as GET or POST /report, through a registration in another module.
    return request.args.get("id", "")
