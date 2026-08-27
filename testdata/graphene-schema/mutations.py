"""The mutations, in the file that never learns it was registered."""

import os

import graphene

from permissions import ReportPermissions


class ExportReport(graphene.Mutation):
    """A caller-named report, exported through a shell.

    The signature is the one every Graphene application above a certain size writes:
    positional-only framework arguments, then the GraphQL arguments as keyword-only
    parameters. There is no request object anywhere in it -- the caller's values ARE the
    parameters, which is why the parameter is the origin.
    """

    ok = graphene.Boolean()

    class Arguments:
        name = graphene.String(required=True)

    class Meta:
        description = "Export a report."
        permissions = [ReportPermissions.MANAGE_REPORTS]

    @classmethod
    def perform_mutation(cls, _root, info, /, *, name):
        os.system("report-tool --export " + name)
        return cls(ok=True)


class RebuildReports(graphene.Mutation):
    """The same shape with nothing the caller can steer, and a declared permission."""

    ok = graphene.Boolean()

    class Meta:
        description = "Rebuild every report."
        permissions = [ReportPermissions.MANAGE_REPORTS]

    @classmethod
    def perform_mutation(cls, _root, info, /):
        os.system("report-tool --rebuild")
        return cls(ok=True)


class ArchiveReport(graphene.Mutation):
    """Declares no permission where its two siblings do, and does nothing dangerous.

    Here for the CONTROL, not for a weakness: `Meta.permissions` is the only thing a
    Graphene schema has that says who may call an operation, and its absence is only
    visible against the operations beside it.
    """

    ok = graphene.Boolean()

    class Arguments:
        report_id = graphene.ID(required=True)

    class Meta:
        description = "Archive a report."

    @classmethod
    def perform_mutation(cls, _root, info, /, *, report_id):
        return cls(ok=True)
