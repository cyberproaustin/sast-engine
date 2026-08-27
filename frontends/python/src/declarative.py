"""Views the application DECLARES and never writes.

A Django REST Framework view is a class with no request handling in it. `queryset`,
`lookup_url_kwarg` and `permission_classes` are class attributes; the framework reads
them, resolves one record out of the URL, runs the permission classes, and answers. The
handler body a source-level analysis looks for does not exist, so an engine that relates
a gate CALL to an operation CALL inside one control-flow graph sees an empty class and
reports nothing about it -- which is how seven confirmed cross-project IDORs walked past
an analysis written for exactly that relation.

What this module lowers is the relation's two operands as the application stated them:
which request key the declared authorization consults, and which request key the
framework resolves the record from. Neither is a call and neither is in a function, so
neither can be recovered from the function IR at any cost; they are facts about the
class, and a frontend is the only thing that can read them.

Resolution is by NAME and program-wide, which is the convention the rest of this
frontend already follows for registrations: a view names `IsProjectAdmin` and the class
is three packages away, and the alternative to a loose name match is not a precise
answer, it is no answer. The base chain IS followed transitively here, unlike the
one-level method inheritance elsewhere, because the declarations this reads are routinely
split across the chain on purpose -- doccano's `BaseDetailAPI` declares the lookup key
and each of its six subclasses declares only the model.
"""

from __future__ import annotations

import ast

# The generic views whose whole purpose is to resolve ONE record out of the URL. A list
# view is not among them: it answers with a collection, and the question this module asks
# -- which record did the caller choose -- has no answer there.
DRF_DETAIL_BASES = frozenset({
    "RetrieveAPIView",
    "UpdateAPIView",
    "DestroyAPIView",
    "RetrieveUpdateAPIView",
    "RetrieveDestroyAPIView",
    "RetrieveUpdateDestroyAPIView",
})

# Every generic that reads `queryset`, detail and list alike. A list view still declares
# authorization and still narrows its query, and its narrowing is judged the same way.
DRF_GENERIC_BASES = DRF_DETAIL_BASES | frozenset({
    "GenericAPIView",
    "ListAPIView",
    "CreateAPIView",
    "ListCreateAPIView",
    "ModelViewSet",
    "ReadOnlyModelViewSet",
    "GenericViewSet",
})

# The hooks an application overrides to narrow what the framework may reach. Their
# ABSENCE is what this module is looking for, so they have to be recognised wherever the
# application put them.
QUERY_OVERRIDES = ("get_queryset", "get_object", "filter_queryset")

# The class attributes that name the request key the framework selects by. `lookup_field`
# names a MODEL field and doubles as the URL kwarg when `lookup_url_kwarg` is unset, which
# is why both are read and why the first one found wins.
LOOKUP_ATTRS = ("lookup_url_kwarg", "lookup_field")

# Where a URL keyword argument is read from. `self` inside the view, `view` inside a
# permission class, and `kwargs` where a method took it as a parameter.
KWARG_HOLDERS = frozenset({"self", "view", "cls"})

# DRF's own object-level hook. A permission class that defines it is handed the RECORD
# the framework selected, which is the relation this analysis is looking for -- stated by
# the application in the place the framework provides for stating it.
OBJECT_HOOK = "has_object_permission"

# What makes a class a permission rather than a view. Matched on the hook names and on the
# base, because an application writes both spellings and the bare base name is not always
# resolvable to `rest_framework.permissions`.
PERMISSION_HOOKS = frozenset({"has_permission", OBJECT_HOOK})

# The names the framework dispatches a request into: the HTTP verbs a Django view answers
# and the actions a DRF viewset routes to. `create`, `update` and `destroy` are here and
# `perform_create` is not, because the first three ARE the request and the last runs inside
# one the framework is already serving.
REQUEST_METHODS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
    "list", "create", "retrieve", "update", "partial_update", "destroy",
})

MAX_BASE_DEPTH = 8


class ClassFacts:
    """One class as the program wrote it: its bases, its attributes, and its methods."""

    __slots__ = ("name", "module", "node", "bases", "attrs", "methods")

    def __init__(self, module: str, node: ast.ClassDef):
        self.name = node.name
        self.module = module
        self.node = node
        self.bases = [_base_name(b) for b in node.bases]
        self.bases = [b for b in self.bases if b]
        self.attrs: dict[str, ast.AST] = {}
        self.methods: dict[str, ast.AST] = {}
        for member in node.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.methods[member.name] = member
            elif isinstance(member, ast.Assign):
                for target in member.targets:
                    if isinstance(target, ast.Name):
                        self.attrs[target.id] = member.value
            elif isinstance(member, ast.AnnAssign) and isinstance(member.target, ast.Name):
                if member.value is not None:
                    self.attrs[member.target.id] = member.value

    @property
    def is_permission(self) -> bool:
        return bool(PERMISSION_HOOKS & set(self.methods)) or any(
            b.endswith("Permission") for b in self.bases)


def _base_name(node: ast.AST) -> str:
    """`generics.RetrieveAPIView` and `RetrieveAPIView` are the same base written twice."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def loc(module: str, node: ast.AST) -> dict:
    return {"file": module, "line": getattr(node, "lineno", 0),
            "column": getattr(node, "col_offset", 0) + 1}


def url_kwargs(node: ast.AST) -> list[tuple[str, ast.AST]]:
    """Every URL keyword argument a subtree reads, and where it read it.

    `self.kwargs["project_id"]`, `view.kwargs.get("project_id")` and the `kwargs["x"]` of a
    method that took the mapping as a parameter. Only the SUBSCRIPT and the `get` spelling
    -- a view that iterates its kwargs is not naming one, and a name this cannot read is a
    stated miss rather than a guess.
    """
    found: list[tuple[str, ast.AST]] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Subscript) and _is_kwargs(child.value):
            name = _string(child.slice)
            if name:
                found.append((name, child))
        elif (isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                and child.func.attr == "get" and _is_kwargs(child.func.value)
                and child.args):
            name = _string(child.args[0])
            if name:
                found.append((name, child))
    return found


def _is_kwargs(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute) and node.attr == "kwargs":
        return isinstance(node.value, ast.Name) and node.value.id in KWARG_HOLDERS
    return isinstance(node, ast.Name) and node.id == "kwargs"


def permission_names(node: ast.AST) -> list[str]:
    """The classes a `permission_classes` expression names.

    DRF composes permissions with the bitwise operators -- `IsAuthenticated &
    (IsProjectAdmin | IsProjectStaffAndReadOnly)` -- and wraps a parameterised one in
    `partial(CanEditLabel, self.queryset)`. Every leaf of that expression is a class that
    RUNS, whichever operator joined it: `|` means either may admit the request, so both
    are consulted and the scope this view was authorized against is their union.
    """
    out: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            out.append(child.id)
        elif isinstance(child, ast.Attribute):
            out.append(child.attr)
    return out


class Program:
    """Every class in the tree, indexed the two ways a declaration reaches one."""

    def __init__(self, modules: list[tuple[str, ast.Module]]):
        self.by_name: dict[str, ClassFacts] = {}
        # Module-level `IsProjectMember = IsAnnotator | IsProjectAdmin` is a permission
        # under a second name, and the views that reference it never mention the three
        # classes it stands for.
        self.aliases: dict[str, list[str]] = {}
        self.registered: set[str] = set()

        for module, tree in modules:
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    self.by_name.setdefault(node.name, ClassFacts(module, node))
                elif (isinstance(node, ast.Assign) and len(node.targets) == 1
                        and isinstance(node.targets[0], ast.Name)
                        and isinstance(node.value, ast.BinOp)):
                    names = permission_names(node.value)
                    if names:
                        self.aliases.setdefault(node.targets[0].id, names)
            self._collect_registrations(tree)

    def _collect_registrations(self, tree: ast.Module) -> None:
        """The classes a URLconf or a router puts on the surface.

        A view nobody registered answers no request, and a class that merely looks like one
        -- an abstract base, a mixin, a serializer -- is not a route. The registration is
        the evidence that this class is reachable, and it is the only evidence there is.
        """
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "as_view":
                name = _base_name(func.value)
                if name:
                    self.registered.add(name)
            elif (isinstance(func, ast.Attribute) and func.attr == "register"
                    and len(node.args) >= 2):
                name = _base_name(node.args[1])
                if name:
                    self.registered.add(name)

    def chain(self, name: str) -> list[ClassFacts]:
        """The class and everything it inherits, nearest first.

        Bounded and by name, which is the same looseness the registration lookups in this
        frontend already accept and for the same reason: the alternative to a name match
        across files is not a better answer, it is nothing at all.
        """
        out: list[ClassFacts] = []
        seen: set[str] = set()
        pending = [(name, 0)]
        while pending:
            current, depth = pending.pop(0)
            if current in seen or depth > MAX_BASE_DEPTH:
                continue
            seen.add(current)
            facts = self.by_name.get(current)
            if facts is None:
                continue
            out.append(facts)
            pending.extend((b, depth + 1) for b in facts.bases)
        return out

    def base_names(self, name: str) -> set[str]:
        """Every base in the chain, whether or not this tree defines it.

        `generics.RetrieveUpdateDestroyAPIView` is defined in DRF and will never be a
        `ClassFacts`, and it is the name that says what the framework will do.
        """
        out: set[str] = set()
        pending = [(name, 0)]
        seen: set[str] = set()
        while pending:
            current, depth = pending.pop(0)
            if current in seen or depth > MAX_BASE_DEPTH:
                continue
            seen.add(current)
            out.add(current)
            facts = self.by_name.get(current)
            if facts is not None:
                pending.extend((b, depth + 1) for b in facts.bases)
        return out

    def permissions_of(self, name: str, depth: int = 0) -> list[ClassFacts]:
        """The permission classes one name stands for, aliases resolved."""
        if depth > 4:
            return []
        facts = self.by_name.get(name)
        if facts is not None and facts.is_permission:
            return [facts]
        out: list[ClassFacts] = []
        for alias in self.aliases.get(name, []):
            out.extend(self.permissions_of(alias, depth + 1))
        return out


def declared_views(modules: list[tuple[str, ast.Module]],
                   function_id) -> list[dict]:
    """The declarative half of every registered view, as facts the core can relate.

    `function_id(module, node)` names a method the way the rest of the frontend does, so a
    view's own handler bodies can be joined to the authorization the class declares
    around them.
    """
    program = Program(modules)
    out: list[dict] = []
    for name in sorted(program.registered):
        view = _view_of(program, name, function_id)
        if view is not None:
            out.append(view)
    return out


def _view_of(program: Program, name: str, function_id) -> dict | None:
    facts = program.by_name.get(name)
    if facts is None:
        return None
    chain = program.chain(name)
    bases = program.base_names(name)
    if not (bases & DRF_GENERIC_BASES):
        return None

    authorizes = _authorizes(program, chain)
    if not authorizes:
        # Nothing was declared about who may reach this view, so there is no scope to
        # compare a selection against. That is a different question -- whether the view
        # is authorized at all -- and it is not this one.
        return None

    view: dict = {
        "id": f"{facts.module}:{facts.name}",
        "framework": "drf",
        "name": facts.name,
        "loc": loc(facts.module, facts.node),
        "authorizes": authorizes,
    }

    handlers = _handlers(chain, function_id)
    if handlers:
        view["handlers"] = handlers
    if relation := _object_relation(program, chain):
        view["objectRelation"] = relation
    if selects := _selects(chain, bases):
        view["selects"] = selects
    if constrains := _constrains(chain):
        view["constrains"] = constrains
    if resolves := _resolves(chain):
        view["resolves"] = resolves
    if target := _target(chain):
        view["target"] = target
    return view


def _authorizes(program: Program, chain: list[ClassFacts]) -> list[dict]:
    """The request keys the declared authorization consults.

    Two places, because applications write both: `permission_classes` as a class
    attribute, and the same assignment inside a `get_permissions()` override, which is how
    a view whose permissions depend on the request states them.
    """
    named: list[str] = []
    for facts in chain:
        if (expr := facts.attrs.get("permission_classes")) is not None:
            named.extend(permission_names(expr))
        for method in facts.methods.values():
            for node in ast.walk(method):
                if not isinstance(node, ast.Assign):
                    continue
                for target in node.targets:
                    if (isinstance(target, ast.Attribute)
                            and target.attr == "permission_classes"):
                        named.extend(permission_names(node.value))

    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for name in named:
        for perm in program.permissions_of(name):
            # A permission's own base is where the kwarg is usually read: doccano's six
            # roles all inherit one `get_project_id`, and a lookup that stopped at the
            # subclass would find no key on any of them.
            for owner in program.chain(perm.name):
                for key, node in url_kwargs(owner.node):
                    if (key, perm.name) in seen:
                        continue
                    seen.add((key, perm.name))
                    out.append({"key": key, "by": perm.name,
                                "loc": loc(owner.module, node)})
    out.sort(key=lambda d: (d["key"], d["by"]))
    return out


def _object_relation(program: Program, chain: list[ClassFacts]) -> str:
    """The declaration that ties the SELECTED record to the caller, if the view made one.

    DRF hands `has_object_permission` the object the framework resolved. A view that
    declares one has related the record to the requester in the place the framework
    provides for it, and this analysis has nothing to say about it.
    """
    for facts in chain:
        for expr in _permission_exprs(facts):
            for name in permission_names(expr):
                for perm in program.permissions_of(name):
                    for owner in program.chain(perm.name):
                        if OBJECT_HOOK in owner.methods:
                            return perm.name
        if OBJECT_HOOK in facts.methods:
            return facts.name
    return ""


def _permission_exprs(facts: ClassFacts) -> list[ast.AST]:
    out: list[ast.AST] = []
    if (expr := facts.attrs.get("permission_classes")) is not None:
        out.append(expr)
    for method in facts.methods.values():
        for node in ast.walk(method):
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Attribute) and t.attr == "permission_classes"
                    for t in node.targets):
                out.append(node.value)
    return out


def _selects(chain: list[ClassFacts], bases: set[str]) -> dict | None:
    """The request key the framework resolves the record from.

    Only a view that answers about ONE record, and only where the key is WRITTEN DOWN.
    DRF defaults `lookup_field` to `pk` when neither attribute is declared, and taking
    that default would mean asserting a URL keyword the route may not even carry -- the
    declaration is the evidence, and its absence is not evidence of `pk`.
    """
    if not (bases & DRF_DETAIL_BASES):
        return None
    for facts in chain:
        for attr in LOOKUP_ATTRS:
            if (key := _string(facts.attrs.get(attr))) is not None:
                return {"key": key, "by": attr, "loc": loc(facts.module, facts.attrs[attr])}
    return None


def _constrains(chain: list[ClassFacts]) -> list[dict]:
    """The request keys the application's own query override narrows by.

    This is the relation when the application wrote one: `Tag.objects.filter(project=
    self.kwargs["project_id"])` in `get_queryset` says the framework may not reach outside
    the authorized project. It is also the SELECTION when the key is a different one --
    a list of annotations narrowed to an example, under a permission about a project.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for facts in chain:
        for hook in QUERY_OVERRIDES:
            method = facts.methods.get(hook)
            if method is None:
                continue
            for key, node in url_kwargs(method):
                if key in seen:
                    continue
                seen.add(key)
                out.append({"key": key, "by": hook, "loc": loc(facts.module, node)})
    out.sort(key=lambda d: d["key"])
    return out


def _resolves(chain: list[ClassFacts]) -> list[dict]:
    """The view's own accessors that stand for a URL keyword argument.

    An application that scopes a bulk operation writes `self.project.examples`, and
    `project` is a property three lines up that fetches the row `self.kwargs["project_id"]`
    names. Nothing in the handler body says so: the body reads an attribute, and a reader
    who does not follow it sees an unconstrained query over every row in the table.

    Emitted so the core can follow the name without following the call. What the accessor
    RETURNS is not modelled and does not need to be -- what matters is that the value came
    from a key, which is the same fact `propagate` carries for every other value.
    """
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for facts in chain:
        for name, method in facts.methods.items():
            for key, node in url_kwargs(method):
                if (name, key) in seen:
                    continue
                seen.add((name, key))
                out.append({"key": key, "by": name, "loc": loc(facts.module, node)})
    out.sort(key=lambda d: (d["by"], d["key"]))
    return out


def _target(chain: list[ClassFacts]) -> dict | None:
    """The queryset the class declared, which is the operation the framework performs."""
    for facts in chain:
        expr = facts.attrs.get("queryset")
        if expr is None:
            continue
        return {"symbol": _dotted(expr), "loc": loc(facts.module, expr)}
    return None


def _dotted(node: ast.AST) -> str:
    """`Example.objects.all()` as the reader wrote it, so a finding can name it."""
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _handlers(chain: list[ClassFacts], function_id) -> list[str]:
    """The methods of this view that ANSWER a request, wherever in the chain they sit.

    A named list rather than everything that is not underscored, because most methods on a
    view class are not handlers: `get_permissions` decides the check, `project` resolves a
    row, `perform_create` runs inside the framework's own create. What a judgement about
    the declared gate governs is the code the framework dispatches a request INTO, and
    these are the names it dispatches by.
    """
    out: list[str] = []
    seen: set[str] = set()
    for facts in chain:
        for name, method in facts.methods.items():
            if name in seen or name not in REQUEST_METHODS:
                continue
            seen.add(name)
            fid = function_id(facts.module, method)
            if fid:
                out.append(fid)
    out.sort()
    return out
