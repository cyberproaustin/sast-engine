from flask import request


def favicon_proxy():
    return request.args.get("url", "")
