"""Operations a GraphQL schema exposes, which no URLconf registers.

A Graphene application answers every request at ONE address. `GraphQLView` is the only
route a URLconf carries, and behind it sit hundreds of separately addressable operations
that a caller names in the request body -- each with its own arguments, its own resolver
and its own declared permissions. Enumerating the view and stopping there says the
application has one entry point when it has three hundred, and every analysis that starts
from an entry point is then silent about all of them: saleor lowered to 29 entry points,
of which the whole GraphQL API was one.

The registration is a CLASS ATTRIBUTE and never a call the program makes:

    class CheckoutMutations(graphene.ObjectType):
        checkout_create_from_order = CheckoutCreateFromOrder.Field()

which is the same structural problem `declarative.py` solved for Django REST Framework,
and this module reuses its class index for exactly that reason. What is different is what
comes out: there the class IS the handler and the facts are the authorization it declared;
here the attribute is a REGISTRATION and what comes out is an entry point pointing at the
resolver in another module entirely.

Program-wide by necessity. `schema.py` names `CheckoutCreateFromOrder` and never defines
it; `checkout_create_from_order.py` defines it and never learns it was registered. Neither
file can answer on its own, which is the same reason the URLconf pass is program-wide.

What this does not model is stated rather than left to show up as a missing operation.
Subscriptions are not enumerated -- a subscription is delivered over a socket this frontend
does not follow, and calling it an operation a caller invokes would be a guess about the
transport. A field registered by a helper the application wrote, rather than by one of the
constructors named below, yields no operation because nothing in the source says what a
caller would write. And a resolver reached only through the framework's own generic
machinery -- a `ModelMutation` subclass that performs the write with no `perform_mutation`
of its own -- is enumerated with NO function, the same way an unresolved route handler is:
the operation exists at a name whether or not this frontend can name the code behind it
(ADR-009).
"""

from __future__ import annotations

import ast

from declarative import ClassFacts, Program, loc

# The base that makes a class a schema TYPE, and therefore its assignments
# registrations. Matched on the bare name, because `graphene.ObjectType` and a bare
# `ObjectType` are the same base written twice and the import that would tell them apart
# is in a file this pass does not read.
SCHEMA_BASES = frozenset({"ObjectType"})

# The methods a mutation class answers in. `perform_mutation` is the hook Graphene's own
# `Mutation` calls once it has resolved arguments; `mutate` is the plain spelling. Both
# are the request, and a class that defines neither is answered by a generic base -- which
# is a registration whose handler did not resolve, not an absent operation.
MUTATION_RESOLVERS = ("perform_mutation", "mutate")

# Parameters the FRAMEWORK supplies rather than the caller. Everything else in a resolver's
# signature is a GraphQL argument the request named -- including `**data` and `**kwargs`,
# which is where a generic mutation receives the caller's whole argument map and the only
# place those values are.
FRAMEWORK_PARAMS = frozenset({"cls", "self", "root", "_root", "info", "_info",
                              "parent", "_parent", "_"})

# What a mutation registration is written as: `SomeMutation.Field()`. The attribute name
# is fixed by Graphene and is the only spelling there is.
FIELD_ATTR = "Field"

# The field constructors an application calls directly on a query type: Graphene's own,
# its connection fields, and the wrappers saleor puts in front of them. Read because they
# are what the source writes; a wrapper this list does not hold yields no operation rather
# than a guessed one.
QUERY_FIELD_CALLS = frozenset({
    "Field", "List", "ConnectionField", "FilterConnectionField", "BaseField",
    "BaseConnectionField", "PermissionsField", "RelayConnectionField",
})

# Where a mutation declares who may call it. Graphene has no such concept; this is the
# convention a Graphene application of any size invents, and saleor spells it exactly this
# way. Its ABSENCE is the fact this pass exists to make visible.
PERMISSION_ATTRS = ("permissions", "permission_required", "required_permissions")

# The identity a declared permission carries on the surface. Uniform on purpose -- see
# `_permissions_of` for the two measurements that made it uniform.
PERMISSION_REF = "Meta.permissions"


def _camel(name: str) -> str:
    """`checkout_create_from_order` -> `checkoutCreateFromOrder`.

    Graphene renames every field this way by default (`auto_camelcase=True`), so the camel
    spelling is the name a caller actually writes and the snake spelling names nothing. An
    operator checking this enumeration against their schema has to see the name the schema
    has.
    """
    head, *rest = name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest if part)


def _call_target(node: ast.AST) -> tuple[str, str]:
    """`CheckoutCreateFromOrder.Field()` -> ("CheckoutCreateFromOrder", "Field")."""
    if not isinstance(node, ast.Call):
        return "", ""
    func = node.func
    if isinstance(func, ast.Attribute):
        owner = func.value
        if isinstance(owner, ast.Name):
            return owner.id, func.attr
        if isinstance(owner, ast.Attribute):
            return owner.attr, func.attr
        return "", func.attr
    if isinstance(func, ast.Name):
        return "", func.id
    return "", ""


def _is_schema_type(program: Program, facts: ClassFacts) -> bool:
    """Whether this class's attributes are schema fields rather than ordinary data.

    The base chain is followed because the schema types an application composes are
    routinely two deep -- saleor's root is `class Mutation(CheckoutMutations, ...)` -- and
    a class whose own base list holds only application names still ends at
    `graphene.ObjectType`.
    """
    return bool(program.base_names(facts.name) & SCHEMA_BASES)


# How a schema is built. The keyword names are Graphene's own signature and every wrapper
# an application writes around it keeps them, which is why the keywords are the evidence
# and the callee's name is only a fallback for the all-positional spelling.
SCHEMA_FACTORIES = frozenset({"Schema", "build_federated_schema", "build_schema"})
ROOT_KINDS = ("query", "mutation", "subscription")


def _callee_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def schema_roots(modules: list[tuple[str, ast.Module]]) -> dict[str, str]:
    """The classes the program hands to its schema, and which root each one is.

    This is the whole difference between enumerating an API and enumerating a data model.
    Every mutation class in saleor is itself a `graphene.ObjectType` -- that is how Graphene
    returns a payload -- so `AccountAddressCreate.user = graphene.Field(User)` reads exactly
    like a registration and is a RESULT field, not an operation. 107 of a first attempt's
    538 operations were that mistake. What separates the two is not the shape: it is that
    somebody composed the class into the schema, and the schema call is the only place
    anybody does.
    """
    roots: dict[str, str] = {}
    for _, tree in modules:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            declared: dict[str, str] = {}
            for kw in node.keywords:
                if kw.arg in ROOT_KINDS and isinstance(kw.value, ast.Name):
                    declared[kw.value.id] = kw.arg
            positional = _callee_name(node) in SCHEMA_FACTORIES
            if not declared and not positional:
                continue
            # `build_federated_schema(Query, mutation=Mutation, ...)` -- the query root is
            # routinely positional even where the rest are named, and it is always first.
            taken = set(declared.values())
            for index, arg in enumerate(node.args[:len(ROOT_KINDS)]):
                kind = ROOT_KINDS[index]
                if kind in taken or not isinstance(arg, ast.Name):
                    continue
                declared[arg.id] = kind
            roots.update(declared)
    # An application that builds its schema somewhere this cannot read still names its
    # roots the way Graphene's documentation does. Used only when nothing else was found,
    # so it can never widen a schema that WAS read.
    if not roots:
        roots = {"Query": "query", "Mutation": "mutation"}
    return roots


class Operation:
    """One field a caller can invoke, and the code behind it."""

    __slots__ = ("field", "kind", "owner", "target", "node", "at",
                 "module", "resolver_node", "permissions")

    def __init__(self, field: str, kind: str, owner: str, target: str,
                 node: ast.AST, at: str):
        self.field = field
        self.kind = kind
        self.owner = owner
        self.target = target
        # Where the registration is written, which is the schema module.
        self.node = node
        self.at = at
        # Where the code behind it is written, filled in when it resolves.
        self.module = at
        self.resolver_node: ast.AST | None = None
        self.permissions: list[tuple[str, str, ast.AST, str]] = []


def _permissions_of(program: Program, name: str) -> list[tuple[str, str, ast.AST, str]]:
    """The permission constants a mutation declares, wherever in its chain they sit.

    Returned as (identity, spelling, node, module). The identity and the spelling are
    deliberately different.

    WHICH permission an operation requires is a design decision about the object it touches.
    WHETHER it requires one is the question a population can answer, and it is the question
    the missing-authorization weaknesses are about -- saleor's `CheckoutCreateFromOrder`
    declares no `Meta.permissions` at all, which is what lets `BaseMutation.check_permissions`
    return True for anyone.

    Taking the permission's own name as the identity asks the first question, and it is the
    wrong one. Measured over saleor twice. The dotted member produced eight advisories, every
    one false: `customerCreate` was reported for not applying `AccountPermissions.MANAGE_STAFF`
    while declaring `AccountPermissions.MANAGE_USERS` three lines down. Narrowing the identity
    to the enum CLASS removed two and left six, still all false, because the domains are split
    finer than the operations are: `pageTypeCreate` declares `PageTypePermissions.
    MANAGE_PAGE_TYPES_AND_ATTRIBUTES` beside peers declaring `PagePermissions.MANAGE_PAGES`,
    and `productReorderAttributeValues` declares `ProductPermissions.MANAGE_PRODUCTS` beside
    peers declaring `ProductTypePermissions.MANAGE_PRODUCT_TYPES_AND_ATTRIBUTES`. So the
    identity is the DECLARATION, one ref for every operation that makes one, and the
    permissions as written are what a reader is shown.
    """
    out: list[tuple[str, str, ast.AST, str]] = []
    seen: set[str] = set()
    for facts in program.chain(name):
        sources: list[ast.AST] = []
        meta = next((m for m in facts.node.body
                     if isinstance(m, ast.ClassDef) and m.name == "Meta"), None)
        for member in (meta.body if meta is not None else []):
            if not isinstance(member, ast.Assign):
                continue
            for target in member.targets:
                if isinstance(target, ast.Name) and target.id in PERMISSION_ATTRS:
                    sources.append(member.value)
        for attr in PERMISSION_ATTRS:
            if (expr := facts.attrs.get(attr)) is not None:
                sources.append(expr)
        for expr in sources:
            consumed = {id(child.value) for child in ast.walk(expr)
                        if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name)}
            for child in ast.walk(expr):
                if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
                    spelling = f"{child.value.id}.{child.attr}"
                elif isinstance(child, ast.Name) and id(child) not in consumed:
                    spelling = child.id
                else:
                    continue
                if spelling in seen:
                    continue
                seen.add(spelling)
                out.append((PERMISSION_REF, spelling, expr, facts.module))
    if not out:
        return []
    # One control, naming every permission it stands for. Emitting one per permission
    # would put the same ref on an operation twice and say nothing more.
    _, _, node, module = out[0]
    return [(PERMISSION_REF, f"{PERMISSION_REF}={','.join(s for _, s, _, _ in out)}",
             node, module)]


def _resolve_handler(program: Program, op: Operation) -> None:
    """The function the framework dispatches this field into, if the program wrote one."""
    if op.kind == "mutation":
        for facts in program.chain(op.target):
            for name in MUTATION_RESOLVERS:
                if (method := facts.methods.get(name)) is not None:
                    op.resolver_node, op.module = method, facts.module
                    return
        return
    # A query field is answered by a method NAMED for it, on the type that declares it.
    # Graphene's own convention, and the only link between the two halves.
    for facts in program.chain(op.owner):
        if (method := facts.methods.get("resolve_" + op.field)) is not None:
            op.resolver_node, op.module = method, facts.module
            return


def operations(program: Program, roots: dict[str, str]) -> list[Operation]:
    """Every field the schema's own root types register, in a stable order.

    Only the roots and what they inherit. A subscription root is deliberately left out:
    it is delivered over a socket this frontend does not follow, and calling it an
    operation a caller invokes would be a guess about the transport.
    """
    out: list[Operation] = []
    surface: list[tuple[ClassFacts, str]] = []
    seen: set[str] = set()
    for root in sorted(roots):
        kind = roots[root]
        if kind == "subscription":
            continue
        for facts in program.chain(root):
            if facts.name in seen or not _is_schema_type(program, facts):
                continue
            seen.add(facts.name)
            surface.append((facts, kind))

    for facts, kind in surface:
        for field, expr in facts.attrs.items():
            if field.startswith("_"):
                continue
            target, call = _call_target(expr)
            # `SomeMutation.Field()` -- and the owner has to be a class this program
            # DEFINES. `graphene.Field(User)` has the same two tokens and registers a
            # result field on a payload type, which is not an operation anybody calls.
            if call == FIELD_ATTR and target in program.by_name:
                op = Operation(field, "mutation", facts.name, target, expr, facts.module)
            elif call in QUERY_FIELD_CALLS and kind == "query":
                op = Operation(field, "query", facts.name, "", expr, facts.module)
            else:
                continue
            _resolve_handler(program, op)
            if op.kind == "mutation":
                op.permissions = _permissions_of(program, op.target)
            out.append(op)
    return out


def graphene_entry_points(modules: list[tuple[str, ast.Module]],
                          function_id) -> tuple[list[dict], set[int]]:
    """Entry points for every GraphQL operation, and the resolvers a caller feeds.

    The second value is the set of resolver AST nodes whose parameters carry what the
    request named. Graphene binds each declared argument to a parameter of the resolver by
    NAME -- there is no request object to read a property off -- so the parameter itself is
    the origin, which is the shape the injected-parameter rule already states.
    """
    program = Program(modules)
    found = operations(program, schema_roots(modules))
    if not found:
        return [], set()

    # An operation is registered once however many schema types compose it: saleor's root
    # `Mutation` inherits `CheckoutMutations`, so the same attribute is reachable under two
    # class names, and emitting both would report an API twice the size of the schema.
    seen: set[str] = set()
    entries: list[dict] = []
    resolvers: set[int] = set()
    for op in found:
        name = _camel(op.field)
        if name in seen:
            continue
        seen.add(name)

        function = ""
        if op.resolver_node is not None:
            function = function_id(op.module, op.resolver_node)
            resolvers.add(id(op.resolver_node))

        detail = {
            "method": "MUTATION" if op.kind == "mutation" else "QUERY",
            # A GraphQL operation is not an HTTP address and is deliberately not spelled as
            # one: every one of these answers at the single URL the URLconf registers, and
            # printing 315 paths would tell an operator the application serves 315
            # addresses. What it does have is a name a caller writes and a verb -- the two
            # halves of a label that can be checked against the schema.
            "path": name,
            "module": op.module,
            "mount": op.owner,
        }
        if op.target:
            # The class behind the registration, named whether or not its code resolved.
            # An unresolved handler is a named gap rather than a blank (ADR-009).
            detail["handler"] = op.target
        entry: dict = {
            "functionId": function,
            "kind": "graphql-operation",
            "framework": "graphene",
            "detail": detail,
            "loc": loc(op.at, op.node),
        }
        if op.permissions:
            entry["middleware"] = [
                {"symbol": ref, "name": spelling, "scope": "route", "loc": loc(module, node)}
                for ref, spelling, node, module in op.permissions
            ]
        entries.append(entry)
    return entries, resolvers


def caller_supplied_params(node: ast.AST) -> set[str]:
    """The resolver parameters Graphene fills from the request.

    Everything the framework supplies is named and excluded; what remains is a GraphQL
    argument, whatever it is called.
    """
    args = getattr(node, "args", None)
    if args is None:
        return set()
    names = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    for extra in (args.vararg, args.kwarg):
        if extra is not None:
            names.append(extra.arg)
    return {n for n in names if n not in FRAMEWORK_PARAMS}
