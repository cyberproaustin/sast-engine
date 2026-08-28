"""The billing subject: the type whose records the cart mutations reach for."""

import graphene


class Invoice(graphene.ObjectType):
    """A record that belongs to whoever the invoice was issued to."""

    total = graphene.String()
    lines = graphene.List(graphene.String)
