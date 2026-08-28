"""The check a mutation makes when it means to relate an invoice to its requester.

Written as a helper taking BOTH the request and the record, which is how a graphene
application states this: there is no request object in the resolver's signature to hang a
decorator on, so the question is asked with two arguments.
"""


def check_can_read_invoice(context, invoice):
    requester = context.user
    if requester and invoice.owner_id == requester.id:
        return True
    raise PermissionError("not your invoice")
