"""SILENT AS APPLICATION SURFACE -- a release script.

A real program start, enumerated as one, and not the application's. It runs when a
maintainer types a build command; nothing an operator deploys ever executes it. Counting
it beside the process the application actually starts in is the same category error as
counting an example route, and one repository in this corpus contributes fifteen of these
against one real entry point.

`devscripts/` counts only because it is the first segment of the repository. Matching a
tooling name at any depth would classify application packages by accident.
"""

from __future__ import annotations

import os

import requests


def publish() -> None:
    requests.post("https://uploads.example/release", json=os.environ)


if __name__ == "__main__":
    publish()
