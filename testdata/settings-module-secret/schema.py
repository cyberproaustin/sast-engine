import graphene


class AccountRegisterInput(graphene.InputObjectType):
    # NEGATIVE, and the second near miss, measured on saleor. A class body is reached
    # from the module's top level and is not part of it, so this is a field declaration
    # rather than a configuration write -- and `description="Password."` is a keyword
    # that ACCOMPANIES the value rather than one that names a default.
    email = graphene.String(description="The email address of the user.", required=True)
    password = graphene.String(description="Password.", required=True)
