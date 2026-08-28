"""The permission constants a mutation names in its `Meta`."""

import enum


class BillingPermissions(enum.Enum):
    MANAGE_INVOICES = "billing.manage_invoices"
