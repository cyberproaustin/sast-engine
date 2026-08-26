"""Django management commands: an entry point that is not a route.

A command runs with everything the application has -- its database, its secrets, its
network -- over arguments a person typed at a shell. Nothing routes to `handle`, so
before this class existed no enumerated entry point reached any of this code and every
defect in it was not judged and found clean but never asked about, which is the failure
ADR-009 exists to prevent.

The trust label is the other half, and it cuts BOTH ways. Somebody who can run
`manage.py` already has the host, so a shell metacharacter they type is not the same
finding as one a stranger posts to a route -- reporting the two at one rank would
overstate this one. And it is emphatically not nothing: operators paste values from
tickets, cron entries and CI variables into these arguments, and the interpolation below
is a real defect. So it is reported, at warning, and it does not fail a build.
"""

from __future__ import annotations

import os
import subprocess

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    """`manage.py probehost <host> --shell` -- argparse fills `handle` in."""

    help = "Check that a host answers."

    def add_arguments(self, parser):
        # What the command accepts, which is where the entry point's inputs are
        # DECLARED. The values themselves arrive as parameters of `handle`, which is
        # where they are classified.
        parser.add_argument("host", help="hostname to probe")
        parser.add_argument("--attempts", type=int, default=1)

    # EXPECTED FINDING -- an operator's argument interpolated into a shell command.
    def handle(self, host, attempts, **options):
        os.system("ping -c %s %s" % (attempts, host))
        return "done"


class ReportCommand(BaseCommand):
    """A second command, reading its option out of the keyword dictionary."""

    def add_arguments(self, parser):
        parser.add_argument("--output", default="/tmp/report.csv")

    # EXPECTED FINDING -- the same value, arriving through `**options` rather than
    # through a named parameter.
    #
    # `**options` is a parameter as much as `host` is, and until it was lowered as one
    # this read produced nothing at all: the name resolved to no value, so the subscript
    # had no base and the whole statement vanished from the IR. A frontend that drops a
    # parameter is not being careful, it is being silent.
    def handle(self, **options):
        subprocess.run("gzip " + options["output"], shell=True)


class Maintenance:
    """SILENT -- a class with a `handle` method that is not a command.

    Nothing derives this from a management-command base, so nothing about it says an
    operator ever runs it, and its parameter is an ordinary argument some other part of
    the program passes. The base class is what decides, not the method name and not the
    directory: keying on `management/commands/` would have enumerated an `__init__.py`
    and missed a command a project keeps somewhere else.
    """

    def handle(self, host):
        os.system("ping -c 1 " + host)


class VacuumCommand(BaseCommand):
    """SILENT -- a command that runs a fixed command line.

    Enumerated as an entry point, because it is one. It reports nothing because nothing
    an operator typed reaches the interpreter: every part of this was written down in
    the source and is the same in every clone of the repository.
    """

    def handle(self, **options):
        os.system("vacuumdb --analyze")
