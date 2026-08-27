"""Keyword arguments bind by declaration name, never by where keywords begin.

The first keyword in a method call with no positional arguments used to arrive at
parameter zero, and parameter zero is `self`. That made a request body become the
receiver: reading `self.hub.base_url` below then looked like reading caller data.

The second keyword shared the same wrong position, so merely removing the false receiver
flow would trade a false positive for a false negative. The command sink holds the other
half of the contract: `username` must reach the parameter named `username`, despite being
the second keyword and the third declared parameter.
"""
import subprocess

from tornado import web


class LoginHandler(web.RequestHandler):
    def post(self):
        supplied = self.request.body
        return self._render(login_error=supplied, username=supplied)

    def _render(self, *, login_error=None, username=None):
        # NEGATIVE. This is application state reached through the receiver. Caller data
        # passed as `login_error` must never bind `self` and taint this redirect target.
        self.redirect(self.hub.base_url)

        # POSITIVE. The later keyword must bind by its own name too; losing this finding
        # would be the recall regression the fixture is designed to expose.
        subprocess.run("echo " + username, shell=True)
        return login_error


application = web.Application([(r"/login", LoginHandler)])
