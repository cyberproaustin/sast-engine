"""The cart subject: the type these mutations are registered to be about."""

import graphene


class Cart(graphene.ObjectType):
    """A shopper's own cart, addressed by a token only its owner was ever given."""

    token = graphene.String()
    lines = graphene.List(graphene.String)
