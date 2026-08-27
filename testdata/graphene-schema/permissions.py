"""The permission constants a mutation names in its `Meta`."""

import enum


class ReportPermissions(enum.Enum):
    MANAGE_REPORTS = "report.manage_reports"
    VIEW_REPORTS = "report.view_reports"
