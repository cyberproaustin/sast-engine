"""The schema: class attributes, and not one call that registers anything.

Every operation this application answers is an assignment in a class body. There is no
`path(...)`, no decorator and no registrar; the only route a URLconf carries is the single
view that serves all of them, and enumerating that view and stopping is how an application
with hundreds of separately addressable operations reads as having one entry point.
"""

import graphene

from mutations import ArchiveReport, ExportReport, RebuildReports
from reports import find_report
from permissions import ReportPermissions


class ReportType(graphene.ObjectType):
    """A schema TYPE, not a root. Its fields are results, not operations.

    The class is an `ObjectType` exactly as the roots below are, and its `title` reads
    letter for letter like a registration. What separates them is not the shape: it is
    that nobody composed this class into the schema.
    """

    title = graphene.String()
    permissions = graphene.List(graphene.String)


class ReportQueries(graphene.ObjectType):
    report = graphene.Field(ReportType, slug=graphene.String())

    @staticmethod
    def resolve_report(root, info, slug=None):
        return find_report(slug)


class ReportMutations(graphene.ObjectType):
    export_report = ExportReport.Field()
    rebuild_reports = RebuildReports.Field()
    archive_report = ArchiveReport.Field()


class Query(ReportQueries):
    pass


class Mutation(ReportMutations):
    pass


schema = graphene.Schema(query=Query, mutation=Mutation)

VISIBLE_TO = [ReportPermissions.VIEW_REPORTS]
