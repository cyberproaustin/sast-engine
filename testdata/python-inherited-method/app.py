"""The route table. Every class in it answers in a base class in another file."""
from tornado import web

from handlers import api


def make_app():
    return web.Application(api.default_handlers)
