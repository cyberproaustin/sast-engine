"""The schema, which is the only place anything says these classes are operations."""

import graphene

from cart.mutations import (
    CartFillFromInvoice,
    CartFillFromInvoiceCleaned,
    CartFillFromInvoiceGated,
    CartFillFromInvoiceOwned,
    CartRename,
)


class CartMutations(graphene.ObjectType):
    cart_fill_from_invoice = CartFillFromInvoice.Field()
    cart_fill_from_invoice_gated = CartFillFromInvoiceGated.Field()
    cart_fill_from_invoice_owned = CartFillFromInvoiceOwned.Field()
    cart_fill_from_invoice_cleaned = CartFillFromInvoiceCleaned.Field()
    cart_rename = CartRename.Field()


class Mutation(CartMutations):
    pass


class Query(graphene.ObjectType):
    version = graphene.String()

    @staticmethod
    def resolve_version(root, info):
        return "1"


schema = graphene.Schema(query=Query, mutation=Mutation)
