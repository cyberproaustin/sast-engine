"""Five mutations registered on the cart, differing only in the facts that decide.

Every one of them is a `graphene.Mutation` on the cart subject, every one decodes a global
id the caller sent, and every one is answered by `perform_mutation`. Nothing about the
SHAPE separates them -- which is the point, because the shape is what a record-selector
channel matched, and it was measured at 0 true out of 23.

What separates them is three facts, and each of the four silent mutations here is silent
for a different one.
"""

import graphene

from billing.access import check_can_read_invoice
from billing.types import Invoice
from cart.types import Cart
from permissions import BillingPermissions


def load_cart(user):
    return {"token": "t", "lines": [], "user": user}


class CartFillFromInvoice(graphene.Mutation):
    """The weakness. No declared permission, and an invoice is not the cart's subject.

    `check_permissions` returns True when `Meta.permissions` is empty, so any caller
    reaches this. The caller then names an INVOICE -- a record belonging to whoever it was
    issued to -- and its lines are copied into a cart stamped with the caller's own
    identity. The requester is right there in `info.context.user`; it is used to label the
    new row and never to ask about the old one.
    """

    cart = graphene.Field(Cart)

    class Arguments:
        id = graphene.ID(required=True)

    class Meta:
        description = "Fill a cart from an invoice."

    @classmethod
    def perform_mutation(cls, _root, info, /, *, id):
        invoice = cls.get_node_or_error(info, id, only_type=Invoice)
        cart = load_cart(info.context.user)
        cart["lines"] = invoice.lines
        return cls(cart=cart)


class CartFillFromInvoiceGated(graphene.Mutation):
    """The same mutation with the declaration made. Silent because the gate is not empty.

    Byte for byte the same body as the one above. The only difference is four words in
    `Meta`, and they are the whole difference between an operation anyone may call and one
    only an invoice manager may -- which is exactly the fact the engine could not read.
    """

    cart = graphene.Field(Cart)

    class Arguments:
        id = graphene.ID(required=True)

    class Meta:
        description = "Fill a cart from an invoice, for staff."
        permissions = [BillingPermissions.MANAGE_INVOICES]

    @classmethod
    def perform_mutation(cls, _root, info, /, *, id):
        invoice = cls.get_node_or_error(info, id, only_type=Invoice)
        cart = load_cart(info.context.user)
        cart["lines"] = invoice.lines
        return cls(cart=cart)


class CartFillFromInvoiceOwned(graphene.Mutation):
    """No declaration either, and silent because the mutation asks the question itself.

    An operation open to every caller is not a weakness when it authorizes per RECORD
    instead of per caller. One call handed both the request and the row is that
    authorization, and it is how a graphene application writes one.
    """

    cart = graphene.Field(Cart)

    class Arguments:
        id = graphene.ID(required=True)

    class Meta:
        description = "Fill a cart from your own invoice."

    @classmethod
    def perform_mutation(cls, _root, info, /, *, id):
        invoice = cls.get_node_or_error(info, id, only_type=Invoice)
        check_can_read_invoice(info.context, invoice)
        cart = load_cart(info.context.user)
        cart["lines"] = invoice.lines
        return cls(cart=cart)


class CartFillFromInvoiceCleaned(graphene.Mutation):
    """The same relation stated one method along, which is where applications put it.

    The resolver hands the row to a method of its own class and that method asks. Nothing
    in `perform_mutation` relates anything, so a judgement confined to one body reports
    this -- and it is correct code.
    """

    cart = graphene.Field(Cart)

    class Arguments:
        id = graphene.ID(required=True)

    class Meta:
        description = "Fill a cart from your own invoice, checked in clean_instance."

    @classmethod
    def clean_instance(cls, info, invoice):
        check_can_read_invoice(info.context, invoice)

    @classmethod
    def perform_mutation(cls, _root, info, /, *, id):
        invoice = cls.get_node_or_error(info, id, only_type=Invoice)
        cls.clean_instance(info, invoice)
        cart = load_cart(info.context.user)
        cart["lines"] = invoice.lines
        return cls(cart=cart)


class CartRename(graphene.Mutation):
    """No declaration, no relation, and silent because the record is the cart's own.

    A storefront's cart mutations declare nothing because a shopper drives their own cart,
    and the cart token is the only way to address one. That absence is a statement about
    CARTS. Reading it as a weakness would be wrong about every sibling in this module,
    which is why the subject is a condition and the absence alone is not a finding.
    """

    cart = graphene.Field(Cart)

    class Arguments:
        id = graphene.ID(required=True)
        label = graphene.String(required=True)

    class Meta:
        description = "Rename your cart."

    @classmethod
    def perform_mutation(cls, _root, info, /, *, id, label):
        cart = cls.get_node_or_error(info, id, only_type=Cart)
        cart["label"] = label
        cart["actor"] = info.context.user
        return cls(cart=cart)
