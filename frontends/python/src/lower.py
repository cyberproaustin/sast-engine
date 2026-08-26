"""Lowers Python into the sast-engine Program IR.

Produces IR and nothing else (ADR-001). It never decides whether anything is a
vulnerability, and the core never learns that Python exists.

Semantic source: the stdlib `ast` module plus explicit scope tracking. That is
weaker than a real type checker, and the frontend says so in its declared
capabilities rather than letting the difference show up as fewer findings
(ADR-003). Upgrading to pyright is a frontend change and nothing else.
"""

from __future__ import annotations

import ast
import re
import os
from typing import Any

from templates import index_templates, resolve_template

IR_VERSION = "0.14.0"
FRONTEND_VERSION = "0.1.0"

FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)

# Statements whose control flow the block builder does not express. A loop's back edge is
# never emitted, `try` is lowered as straight-line code, and a `match`'s arms all appear
# to run. Inside one of these, `self.current` names a block that would claim an edge is
# unavoidable when it is not -- so a flow lowered here states no block at all, and the
# core keeps it. The bias goes one way on purpose: a flow with no position is kept, a
# flow with a wrong position could be dropped, and a dropped flow is a missed weakness.
UNMODELLED_STATEMENTS = tuple(
    node
    for node in (
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        getattr(ast, "TryStar", None),
        getattr(ast, "Match", None),
    )
    if node is not None
)

# The language's own containers. `payload.update(request.form)` and a record update are
# the same three words, and only one of them touches a store whose records someone owns.
# This frontend has no type checker, so it answers where it can — from an annotation the
# author wrote, or from a literal it can see — and stays silent otherwise. Silence is
# read by the core as "unknown", never as "not a container".
HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

# Base classes whose subclasses Flask dispatches by HTTP verb.
# Every base class whose subclass answers a request by the verb its methods are named
# after. Flask's own two, plus the Resource of Flask-RESTX, Flask-RESTful and
# Flask-AppBuilder -- which three of the applications in the clean corpus are built on,
# and whose routes were invisible because the base class was not on this list.
VIEW_BASES = frozenset({
    "MethodView", "View", "Resource", "ModelRestApi", "BaseApi", "ModelView",
    "HTTPMethodView",
})

# The builtins a rule in this project has anything to say about. Deliberately a short
# list rather than everything in the module: a name is only qualified as a builtin when
# nothing in the file defines or imports it, and a short list keeps a shadowed name in
# some other file from being labelled as the language's.
PYTHON_BUILTINS = frozenset({
    "open", "eval", "exec", "compile", "__import__", "input", "int", "float",
    "getattr", "setattr", "delattr", "globals", "locals", "vars",
})

BUILTIN_CONTAINERS = frozenset({"dict", "list", "set", "frozenset", "bytearray", "tuple", "Counter", "defaultdict", "OrderedDict"})


# --- Route binders ----------------------------------------------------------
#
# WHICH FRAMEWORK a decorator belongs to is a property of the object it is bound to, not
# of the file it sits in. `@router.get("/me")` on a FastAPI `APIRouter` and
# `@app.route("/me")` on a Flask app are two frameworks, and a file that imports both --
# which is what an application with a Flask admin and a FastAPI API looks like -- gets one
# answer per decorator or a wrong answer for half of them.
#
# The constructor names each framework binds a route receiver with, and the module each
# one comes from. The module is checked first (the import table already resolves it), and
# the bare name is the fallback for a constructor whose import could not be resolved.
ROUTER_CONSTRUCTORS = {
    "APIRouter": "fastapi",
    "FastAPI": "fastapi",
    "Flask": "flask",
    "Blueprint": "flask",
    "Namespace": "flask",
    "Api": "flask",
    "Sanic": "sanic",
}

# The import root a constructor came from decides the framework when the two disagree:
# `Blueprint` is Flask's and `APIRouter` is FastAPI's, but an application is free to
# import either from a wrapper of its own.
ROUTER_MODULE_FRAMEWORKS = (
    ("fastapi", "fastapi"),
    ("starlette", "fastapi"),
    ("flask", "flask"),
    ("sanic", "sanic"),
)

# The keyword each framework spells a mount prefix with. A router constructed under a
# prefix serves every route registered on it BELOW that prefix, and a path recorded
# without it names an address that answers nothing.
PREFIX_KEYWORDS = ("prefix", "url_prefix", "path")

# What a path that could not be resolved is called. `*` was what this used to print, and
# `*` reads as "matches everything" -- a claim about the route that is both different from
# and stronger than "this frontend could not read the expression". ADR-009 asks for the
# route to exist either way; it does not ask for it to lie about its address.
UNRESOLVED_PATH = "<unresolved>"


def unresolved_path(expr: str = "") -> str:
    """The marker for a path the frontend could not read, naming the expression."""
    return f"<unresolved:{expr}>" if expr else UNRESOLVED_PATH


def is_unresolved_path(path: str) -> bool:
    return path.startswith("<unresolved")


def _is_environ(node: ast.AST) -> bool:
    """`os.environ` however the file spelled the import."""
    if isinstance(node, ast.Attribute):
        return node.attr == "environ"
    return isinstance(node, ast.Name) and node.id == "environ"


def join_route(prefix: str, path: str) -> str:
    """A mount prefix concatenated with the path registered under it."""
    if not prefix:
        return path
    if not path:
        return prefix
    return prefix.rstrip("/") + "/" + path.lstrip("/")


# --- Django URLconf ---------------------------------------------------------
#
# Django registers a route by CALL, inside a list, in a file the handler knows nothing
# about. Recognised by SHAPE and never by file name: `urls.py` is a convention and an
# application is free to put a URLconf anywhere, so the registration itself is the only
# thing that can identify one.

# `path` and `re_path` from `django.urls`, plus the `url` of `django.conf.urls`, which is
# what every application written before Django 2.0 still spells its routes with.
DJANGO_REGISTRARS = frozenset({"path", "re_path", "url"})

# `<int:pk>`, `<slug:name>` and the bare `<pk>` are one parameter written three ways.
# `:pk` is the spelling every other framework model in this engine emits, so a Django
# route and an Express route can be read by the same eye.
DJANGO_CONVERTER = re.compile(r"<(?:[^<>:]+:)?([^<>:]+)>")

# The verb a class-based view answers by naming a method after it. Django dispatches
# `get` to GET exactly as Flask does, so one `as_view()` in a URLconf stands for as many
# routes as the class has verbs -- and the class is where they are, not the URLconf.
DJANGO_VERB_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

# What a class exposes to a request when it names no method after a verb or an action. A
# TemplateView subclass defines `get_context_data` and nothing else and answers every GET
# all the same; pointing the route at the hook is the difference between a handler that is
# in the surface and a class that is nowhere in it (ADR-009).
DJANGO_HOOKS = ("dispatch", "get_context_data", "form_valid", "get_queryset", "get_object",
                "perform_create")

# What `router.register("checks", CheckViewSet)` becomes. One line of a Django REST
# Framework router is six routes, and the viewset carries a method for each of them.
DRF_ROUTES = (
    ("GET", "/", "list"),
    ("POST", "/", "create"),
    ("GET", "/<pk>/", "retrieve"),
    ("PUT", "/<pk>/", "update"),
    ("PATCH", "/<pk>/", "partial_update"),
    ("DELETE", "/<pk>/", "destroy"),
)


# --- Tornado URLSpec --------------------------------------------------------
#
# Tornado does not register a route with a CALL. A module declares a module-level list of
# TUPLES and the application collects those lists, so a tuple in a list is the whole
# registration -- and a frontend that looks for calls sees nothing at all. JupyterHub
# enumerated 9 entry points against 62 real handler registrations, and every one of the 9
# came out of its `examples/` directory: zero of the application that ships.

# The two spellings of the same tuple. `tornado.web.url(pattern, Handler)` and
# `URLSpec(pattern, Handler)` build the object the tuple is shorthand FOR, and an
# application mixes the two inside one table.
TORNADO_REGISTRARS = frozenset({"url", "URLSpec"})

# A Tornado handler answers in a method named after the verb, exactly as a Django
# class-based view does. One tuple is therefore as many entry points as the class has
# verbs, and the class is where they are -- never the table.
TORNADO_VERB_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

# What a handler exposes to a request when it names no verb at all. `prepare` runs ahead
# of every verb whatever it is, and a WebSocket handler answers in `open` and `on_message`
# and has no verb to be named after -- pointing the route at one of those is the difference
# between a handler that is in the surface and a class that is nowhere in it (ADR-009).
TORNADO_HOOKS = ("prepare", "on_message", "open")


# Python test-file conventions.
TEST_PATH = re.compile(r"(^|/)(tests?|testing|e2e)/|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)conftest\.py$")


def is_test_module(module: str) -> bool:
    """Ships with the code but does not run in production."""
    return bool(TEST_PATH.search(module))


def module_id(root: str, path: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


def _bound_names(target: ast.AST) -> list[ast.Name]:
    """Every name a binding target binds, however deeply it nests."""
    if isinstance(target, ast.Name):
        return [target]
    if isinstance(target, (ast.Tuple, ast.List)):
        out: list[ast.Name] = []
        for element in target.elts:
            out.extend(_bound_names(element))
        return out
    if isinstance(target, ast.Starred):
        return _bound_names(target.value)
    return []


def constant_text(value: Any) -> str | None:
    """The text of a constant, for the kinds a rule can read.

    Booleans before numbers: in Python `True` IS an int, and rendering it as `1` would
    make a comparison against a flag look like a comparison against a threshold.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        return value
    return None


def loc_of(module: str, node: ast.AST) -> dict:
    return {
        "file": module,
        "line": getattr(node, "lineno", 0),
        "column": getattr(node, "col_offset", 0) + 1,
    }


def dotted_module(module: str) -> str:
    """The name an importer writes for a module id."""
    return module[:-3].replace("/", ".") if module.endswith(".py") else module


def django_route_text(node: ast.AST) -> str | None:
    """The literal part of a route, which is all of it except where a setting is in it.

    A root URLconf that mounts everything under `f"{prefix}admin/"` writes the prefix as an
    f-string over a setting no frontend without an evaluator will ever read. The STATIC
    text is still the route for every deployment that leaves the setting at its default,
    so it is kept: the cost is a prefix that may be wrong, and the alternative was the
    route not existing at all (ADR-009).
    """
    if isinstance(node, ast.Constant):
        return _unanchored(node.value) if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        return _unanchored("".join(
            part.value for part in node.values
            if isinstance(part, ast.Constant) and isinstance(part.value, str)))
    return None


def _unanchored(route: str) -> str:
    """A regex route without its anchors, which are position rather than path.

    Stripped from each FRAGMENT rather than from the finished path: a mounted URLconf
    anchors its own patterns, and `api/v3/` composed with `^ping/$` puts the caret in the
    middle of the path where nothing would ever remove it.

    Shared with the Tornado model below rather than written twice: `re_path(r"^ping/$")`
    and a URLSpec's `r"/health$"` are one regex written for two registrars.
    """
    if route.startswith("^"):
        route = route[1:]
    if route.endswith("$"):
        route = route[:-1]
    return route


def django_included(node: ast.AST) -> ast.AST | None:
    """The URLconf an `include(...)` names, or None when this is not one.

    `include("hc.api.urls")`, `include(check_urls)`, `include(router.urls)` and
    `include((patterns, "app"))` are one registration wearing four different clothes.
    """
    if not isinstance(node, ast.Call):
        return None
    name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
    if name != "include" or not node.args:
        return None
    first = node.args[0]
    if isinstance(first, ast.Tuple) and first.elts:
        # `include((patterns, "app_namespace"))`. A namespace names the route and is not
        # part of its path.
        return first.elts[0]
    return first


def django_local_name(node: ast.AST | None) -> str | None:
    """The name of a URLconf defined in this same file, out of what `include` was given."""
    if isinstance(node, ast.Name):
        return node.id
    # `include(router.urls)` -- a DRF router is a list of routes wearing a property.
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id
    return None


def django_route_path(route: str) -> str:
    """A Django route written as the path the rest of the engine reads.

    `<int:pk>` and `(?P<pk>[0-9]+)` are the same parameter written for the two registrars,
    and both become `:pk`. The rest of a pattern is left exactly as it was written, because
    rewriting a regex into a path is guesswork and a path that is wrong is worse than one
    that is ugly.
    """
    route = _named_groups(route)
    route = DJANGO_CONVERTER.sub(r":\1", route)
    # Django routes are written without a leading slash: the mount point supplies it.
    return "/" + route.lstrip("/")


def _named_groups(pattern: str) -> str:
    """`(?P<code>[\\w-]+)` -> `:code`, by matching the group's own parentheses.

    Counted rather than matched with a regex of our own: a named group holds parentheses
    of its own routinely -- `(?P<code>(a|b))` -- and a non-greedy match ends the parameter
    in the middle of it, which puts regex punctuation into the middle of a path.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if not pattern.startswith("(?P<", i):
            out.append(pattern[i])
            i += 1
            continue
        close = pattern.find(">", i)
        if close < 0:
            out.append(pattern[i])
            i += 1
            continue
        out.append(f":{pattern[i + 4:close]}")
        depth, i = 1, close + 1
        while i < len(pattern) and depth:
            if pattern[i] == "\\":
                i += 1
            elif pattern[i] == "(":
                depth += 1
            elif pattern[i] == ")":
                depth -= 1
            i += 1
    return "".join(out)


def django_entry_point(function_id: str, method: str, path: str) -> dict:
    return {
        "functionId": function_id,
        "kind": "http-route",
        "framework": "django",
        "detail": {"method": method, "path": path},
    }


def tornado_route_path(pattern: str) -> str:
    """A Tornado URL regex written as the path the rest of the engine reads.

    A Tornado pattern is a regex and nothing else, so both kinds of capture in it are a
    parameter: a named group is the name Tornado passes as a keyword argument, and an
    unnamed one is a positional argument whose only name is where it sits. `:name` is the
    spelling every other framework model in this engine emits, so a Tornado route and an
    Express route can be read by the same eye.
    """
    pattern = _tornado_unnamed_groups(_named_groups(_unanchored(pattern)))
    # Tornado patterns are matched against the request path, which always begins with a
    # slash. A table's own patterns carry it; a table an application mounts under a prefix
    # -- JupyterHub serves every one of its handlers under `/hub` -- writes the empty
    # pattern for the mount point itself.
    return "/" + pattern.lstrip("/")


def tornado_pattern_text(node: ast.AST) -> str | None:
    """The pattern of a registration, when this literal is one at all.

    The leading slash is the whole test. A two-element tuple of a string and a class is an
    extremely common record -- a choices list, a dispatch table, a registry of exporters --
    and what separates the one that is a route is that its first element is a PATH.
    Without that test, a table of `("draft", DraftState)` reads as a route table, and a
    surface that invents entry points is worse than one that misses them (ADR-009).
    """
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return None
    unanchored = _unanchored(node.value)
    return node.value if unanchored == "" or unanchored.startswith("/") else None


def _tornado_unnamed_groups(pattern: str) -> str:
    """`([^/]+)` -> `:arg1`, numbered by position, by matching the group's own parentheses.

    Counted rather than matched with a regex of our own, for the reason `_named_groups`
    counts: a capture holds parentheses of its own routinely -- `/error/((\\d+)|x)` -- and
    a non-greedy match ends the parameter in the middle of one, which puts regex
    punctuation into the middle of a path.

    A `(?...)` group captures nothing and is left exactly as it was written: Tornado passes
    the verb method one argument per CAPTURE, so a non-capturing group is not a parameter
    and numbering it would shift every parameter after it.
    """
    out: list[str] = []
    index, i = 0, 0
    while i < len(pattern):
        if pattern[i] == "\\":
            out.append(pattern[i:i + 2])
            i += 2
            continue
        if pattern[i] != "(" or pattern.startswith("(?", i):
            out.append(pattern[i])
            i += 1
            continue
        index += 1
        out.append(f":arg{index}")
        depth, i = 1, i + 1
        while i < len(pattern) and depth:
            if pattern[i] == "\\":
                i += 1
            elif pattern[i] == "(":
                depth += 1
            elif pattern[i] == ")":
                depth -= 1
            i += 1
    return "".join(out)


def tornado_entry_point(function_id: str, method: str, path: str) -> dict:
    return {
        "functionId": function_id,
        "kind": "http-route",
        "framework": "tornado",
        "detail": {"method": method, "path": path},
    }


class ModuleLowerer:
    """Lowers one module. Imports and module-level defs are resolved by name."""

    def __init__(self, root: str, path: str, tree: ast.Module, defs: dict[str, str],
                 templates: dict | None = None, resource_paths: dict[str, str] | None = None,
                 django_prefixes: dict[str, str] | None = None,
                 class_members: dict[str, dict[str, str]] | None = None,
                 base_members: dict[str, dict[str, str]] | None = None):
        self.module = module_id(root, path)
        # Every view under the root, read once for the whole program.
        self.templates = templates or {}
        self.tree = tree
        self.global_defs = defs
        self.imports: dict[str, str] = {}
        # Every method of every class in the program, by the name a registration would
        # write for the class. A class-based view is registered by CLASS and answers by
        # METHOD, so the registration names one thing and the entry points are another.
        self.class_members = class_members or {}
        # What a class INHERITS, one level up and resolved across the program. A registered
        # Tornado handler is free to define no verb of its own -- the subclass carries the
        # model and the permission scope and the base carries `get` and `post` -- and
        # without this such a registration reaches a class with nothing in it.
        self.base_members = base_members or {}
        # Where another module mounted this one. Django gives a whole URLconf its prefix
        # from a file that URLconf never mentions, so this is the only way the routes
        # below can learn the path they are actually served at.
        self.django_prefix = (django_prefixes or {}).get(dotted_module(self.module), "")
        self.functions: list[dict] = []
        self.entry_points: list[dict] = []
        # Which class each method belongs to, so `self.x()` has something to resolve
        # against. Built once here rather than tracked during the walk, because the
        # walk visits functions without their surrounding context.
        self.class_of: dict[int, str] = {}
        # Classes Flask dispatches by HTTP verb, by their declared base.
        self.view_classes: set[str] = set()
        # Paths from registrations anywhere in the program, so a class registered in one
        # file learns its path even though it is defined in another.
        self.decorated_view_paths: dict[str, str] = dict(resource_paths or {})
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Registered somewhere in the program, which proves it is a view whatever
                # it inherits from -- and applications routinely define their own base.
                if node.name in self.decorated_view_paths:
                    self.view_classes.add(node.name)
                for base in node.bases:
                    name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
                    if name in VIEW_BASES:
                        self.view_classes.add(node.name)
                # `@namespace.route("/things")` on a class is how Flask-RESTX and
                # Flask-RESTful give a Resource its path, and it is a registration as
                # much as `add_url_rule` is. The path is right there on the decorator.
                for dec in node.decorator_list:
                    if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                        continue
                    if dec.func.attr != "route" or not dec.args:
                        continue
                    first = dec.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        self.view_classes.add(node.name)
                        self.decorated_view_paths[node.name] = first.value
                for member in node.body:
                    if isinstance(member, FUNCTION_NODES):
                        self.class_of[id(member)] = node.name
        # Names bound at module level, so a function can resolve one it did not define.
        # `log = logging.getLogger(__name__)` at the top of a file and `log.info(...)`
        # inside a handler are the same object, and without this link the second is a
        # method call on nothing -- which is most of Python logging.
        self.module_scope: dict[str, str] = {}
        # Every name bound to a string, so a route written as a name or a concatenation
        # resolves to the address it is actually served at rather than to nothing.
        self.string_bindings: dict[str, ast.AST] = {}
        # Route receivers: which framework each one belongs to, and the prefix it mounts
        # its routes under.
        self.binder_framework: dict[str, str] = {}
        self.binder_prefix: dict[str, ast.AST] = {}
        self._collect_imports()
        self._collect_route_binders()

    def _collect_imports(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                # A RELATIVE import resolves against this module's own package, and that
                # package is knowable: it is the module's own path with the last segment
                # dropped once per leading dot. Skipping these left `from . import views`
                # binding nothing at all -- which is how Django's own tutorial writes a
                # URLconf, so every route in such a file pointed at a name that resolved
                # to nothing, and every call through one stopped at the import.
                module = node.module or ""
                if node.level:
                    package = dotted_module(self.module).split(".")[:-node.level]
                    module = ".".join([*package, module] if module else package)
                if not module:
                    continue
                for alias in node.names:
                    local = alias.asname or alias.name
                    self.imports[local] = f"{module}.{alias.name}"

    # --- Route receivers and the paths they are mounted at ---------------------
    #
    # A decorator says which verb and which path; the object it is bound to says which
    # framework and which prefix. Both halves are needed before an entry point can state
    # its own address, and the second half is what a per-FILE framework guess threw away.

    def _collect_route_binders(self) -> None:
        """`router = APIRouter(prefix=...)` -- the framework and prefix of each receiver.

        Walked over the whole tree rather than the module body: an application factory
        (`def create_app(): app = Flask(__name__)`) is where a great deal of real code
        constructs its app, and a receiver bound inside one is a receiver all the same.
        """
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            else:
                continue
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                # First binding wins, the way the reader of the file sees it: a name
                # reassigned later is still the one the decorators below it were written
                # against.
                if isinstance(value, ast.Call):
                    framework = self._constructor_framework(value.func)
                    if framework and target.id not in self.binder_framework:
                        self.binder_framework[target.id] = framework
                        prefix = self._prefix_argument(value)
                        if prefix is not None:
                            self.binder_prefix[target.id] = prefix
                if target.id not in self.string_bindings:
                    self.string_bindings[target.id] = value

        # `api.register_blueprint(bp, url_prefix="/v2")` and FastAPI's
        # `app.include_router(router, prefix="/api")` mount a receiver that was
        # constructed without a prefix of its own. Same fact, stated at the mount.
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in ("register_blueprint", "include_router", "add_namespace"):
                continue
            if not node.args or not isinstance(node.args[0], ast.Name):
                continue
            name = node.args[0].id
            prefix = self._prefix_argument(node)
            if prefix is not None and name not in self.binder_prefix:
                self.binder_prefix[name] = prefix

    def _constructor_framework(self, func: ast.AST) -> str | None:
        """The framework a route receiver's constructor belongs to, or None."""
        if isinstance(func, ast.Name):
            name, origin = func.id, self.imports.get(func.id, "")
        elif isinstance(func, ast.Attribute):
            name = func.attr
            root = func.value.id if isinstance(func.value, ast.Name) else ""
            origin = f"{self.imports.get(root, root)}.{name}"
        else:
            return None
        if name not in ROUTER_CONSTRUCTORS:
            return None
        root = origin.split(".")[0]
        for module, framework in ROUTER_MODULE_FRAMEWORKS:
            if root == module or root.startswith(module + "_"):
                return framework
        return ROUTER_CONSTRUCTORS[name]

    @staticmethod
    def _prefix_argument(call: ast.Call) -> ast.AST | None:
        for kw in call.keywords:
            if kw.arg in PREFIX_KEYWORDS:
                return kw.value
        return None

    def binder_prefix_text(self, receiver: ast.AST) -> str:
        """The mount prefix of the object a decorator is bound to."""
        if not isinstance(receiver, ast.Name):
            return ""
        expr = self.binder_prefix.get(receiver.id)
        return "" if expr is None else self.path_text(expr)

    def path_text(self, node: ast.AST, seen: frozenset[str] = frozenset()) -> str:
        """A route path as it was written, resolved as far as the file allows.

        A path is a name, a concatenation or an f-string at least as often as it is a
        literal, and every one of those used to lower to `*`. What cannot be resolved is
        NAMED -- `<unresolved:baseUriPath>/api` says which expression stood in the way,
        which is the difference between an operator being able to look it up and not.
        """
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else unresolved_path()
        if isinstance(node, ast.Name):
            # A name that resolves to a string is that string; one that does not is named
            # rather than dropped, and the cycle guard is what keeps `x = x + "/y"` finite.
            bound = self.string_bindings.get(node.id)
            if bound is not None and node.id not in seen:
                text = self.path_text(bound, seen | {node.id})
                if not is_unresolved_path(text):
                    return text
            return unresolved_path(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.path_text(node.left, seen) + self.path_text(node.right, seen)
        if isinstance(node, ast.JoinedStr):
            out = []
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    out.append(part.value)
                elif isinstance(part, ast.FormattedValue):
                    out.append(self.path_text(part.value, seen))
                else:
                    out.append(unresolved_path())
            return "".join(out)
        if isinstance(node, ast.Attribute):
            return unresolved_path(ast.unparse(node))
        if isinstance(node, ast.Call):
            return self._call_path_text(node, seen)
        return unresolved_path()

    def _call_path_text(self, node: ast.Call, seen: frozenset[str]) -> str:
        """The two calls a mount prefix is routinely written as.

        `os.environ.get("PREFIX", "/hub")` is the DEFAULT for every deployment that leaves
        the variable unset, which is the same judgement `django_route_text` already makes
        about a setting interpolated into a URLconf: the static text is the route until an
        operator changes it, and the alternative was no path at all (ADR-009). `.rstrip("/")`
        and its siblings are how the same code then normalises it.
        """
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in ("strip", "rstrip", "lstrip"):
                base = self.path_text(func.value, seen)
                chars = node.args[0].value if (
                    node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)) else None
                if not is_unresolved_path(base):
                    if func.attr == "strip":
                        return base.strip(chars) if chars else base.strip()
                    if func.attr == "rstrip":
                        return base.rstrip(chars) if chars else base.rstrip()
                    return base.lstrip(chars) if chars else base.lstrip()
                return base
            if func.attr == "get" and len(node.args) > 1 and _is_environ(func.value):
                return self.path_text(node.args[1], seen)
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name == "getenv" and len(node.args) > 1:
            return self.path_text(node.args[1], seen)
        return unresolved_path(ast.unparse(func))

    def lower(self, django: list[dict], registered: set[str]) -> None:
        """Lowers this module, given what the whole program's URLconfs registered.

        `django` is this module's own Django routes and `registered` is every handler any
        URLconf in the program reached. Both are resolved before this runs because a
        URLconf registers classes that are defined in OTHER files, and the file that
        defines one has to know that it was registered.
        """
        # Where a class-based view is registered, so its methods can carry a real path
        # rather than the class name. Collected first because the registration usually
        # sits below the class it points at.
        view_paths = self._view_registration_paths()

        self.functions.append(FunctionLowerer(self, self.tree).lower())

        for node in ast.walk(self.tree):
            if isinstance(node, FUNCTION_NODES):
                fn = FunctionLowerer(self, node).lower()
                self.functions.append(fn)
                # EVERY route decorator, not the first. FastAPI applications stack them
                # -- `@router.get("/x")` and `@router.get("/x/")` on one handler -- and
                # returning at the first match lost the rest.
                found = self.entry_points_for(node, fn["id"])
                if not found:
                    single = self.class_view_entry_point(node, fn["id"], view_paths)
                    if single and single["functionId"] not in registered:
                        found = [single]
                # A test file's routes are not the application's attack surface: a test
                # client is CALLED exactly as a router is REGISTERED, and a route that
                # exists only in a test does not exist in the program that is deployed.
                if not is_test_module(self.module):
                    self.entry_points.extend(found)

        if not is_test_module(self.module):
            self.entry_points.extend(self._url_rule_entry_points())
            self.entry_points.extend(self._router_entry_points())
            self.entry_points.extend(self.tornado_entry_points())
            self.entry_points.extend(django)
        self._collect_resource_paths()

    # --- Flask class-based views and add_url_rule ------------------------------
    #
    # Decorators are not the only way Flask registers a route, and a model that only
    # knew `@app.route` enumerated ZERO entry points of a 1,012-function Flask forum
    # while the frontend declared Flask support. A capability that is declared and
    # absent is worse than one that was never claimed (ADR-003).

    def _view_registration_paths(self) -> dict[str, str]:
        """Class name -> route path, from any call that registers `X.as_view(...)`.

        Structural rather than name-based: the shape is a call carrying a `view_func`
        keyword whose value is `SomeClass.as_view(...)`, which is how Flask registers a
        class-based view whatever the surrounding helper is called. flaskbb wraps it in
        `register_view(bp, routes=[...], view_func=Search.as_view("search"))`; Flask's
        own `add_url_rule("/x", view_func=...)` is the same shape with the path first.
        """
        out: dict[str, str] = {}
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            cls = None
            for kw in node.keywords:
                if kw.arg != "view_func" or not isinstance(kw.value, ast.Call):
                    continue
                f = kw.value.func
                if isinstance(f, ast.Attribute) and f.attr == "as_view" and isinstance(f.value, ast.Name):
                    cls = f.value.id
            if not cls:
                continue
            for path in self._paths_in(node):
                out.setdefault(cls, path)
        return out

    @staticmethod
    def _paths_in(node: ast.Call) -> list[str]:
        """Route paths written as literals in this call, positionally or by keyword."""
        found = []
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("/"):
                found.append(arg.value)
        for kw in node.keywords:
            if kw.arg in ("rule", "routes", "route"):
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    found.append(kw.value.value)
                elif isinstance(kw.value, (ast.List, ast.Tuple)):
                    found += [e.value for e in kw.value.elts
                              if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        return found

    def class_view_entry_point(self, node: ast.AST, function_id: str, view_paths: dict) -> dict | None:
        """A method of a class-based view is a handler for the verb it is named after.

        Flask calls `get` for GET and `post` for POST on a `MethodView` subclass. That is
        the framework's contract and it holds whether or not the registration that gives
        the class its path can be found, so the route is enumerated either way -- with the
        class name standing in for the path when it cannot (ADR-009: a route that exists
        must appear, even where the engine knows least about it).
        """
        cls = self.class_of.get(id(node))
        if cls is None or cls not in self.view_classes:
            return None
        name = getattr(node, "name", "")
        method = name.upper()
        if method not in HTTP_METHODS:
            # A framework that dispatches through ONE method names it rather than the
            # verb: indico's request handlers answer in `_process`, and `_process_GET`
            # and `_process_POST` where they differ. The class is already known to be a
            # view -- something registered it -- so there is nothing to be wrong about
            # here except which verb to print.
            lowered = name.lower().lstrip("_")
            base, _, suffix = lowered.partition("_")
            if base not in ("process", "handle", "dispatch"):
                return None
            method = suffix.upper() if suffix.upper() in HTTP_METHODS else "ANY"
        return {
            "functionId": function_id,
            "kind": "http-route",
            "framework": "flask",
            "detail": {
                "method": method.upper(),
                "path": self.decorated_view_paths.get(cls) or view_paths.get(cls, cls),
            },
        }

    def _collect_resource_paths(self) -> None:
        """`api.add_resource(ThingResource, "/things")` -- the path for a class.

        Flask-RESTful and its variants register a Resource by CALL rather than by
        decorator, and the class already answers by verb. Only the PATH was missing, so
        the routes were enumerated with the class name standing in for it -- which is
        honest and much less useful than the path the registration plainly carries.
        """
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if not node.func.attr.startswith("add_") or "resource" not in node.func.attr:
                continue
            if len(node.args) < 2 or not isinstance(node.args[0], ast.Name):
                continue
            path = node.args[1]
            if isinstance(path, ast.Constant) and isinstance(path.value, str):
                self.view_classes.add(node.args[0].id)
                self.decorated_view_paths.setdefault(node.args[0].id, path.value)

    def _url_rule_entry_points(self) -> list[dict]:
        """`add_url_rule("/path", view_func=some_function)` pointing at a plain function."""
        out = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Attribute) and node.func.attr == "add_url_rule"):
                continue
            # `view_func` is Flask's third parameter, so it arrives either by keyword or
            # as the third positional argument: add_url_rule(rule, endpoint, view_func).
            ref = None
            for kw in node.keywords:
                if kw.arg == "view_func" and isinstance(kw.value, ast.Name):
                    ref = kw.value.id
            if ref is None and len(node.args) >= 3 and isinstance(node.args[2], ast.Name):
                ref = node.args[2].id
            if ref is None:
                continue

            # A class-based view registered this way gets its path from here; its methods
            # are already entry points by the framework's verb contract.
            if ref in self.view_classes:
                continue
            target = self.global_defs.get(f"{self.module}:{ref}")
            if not target:
                continue
            paths = self._paths_in(node)
            path = paths[0] if paths else (
                self.path_text(node.args[0]) if node.args else unresolved_path())
            # `add_url_rule(..., methods=["POST"])` is the same declaration the decorator
            # makes, and GET was being applied over the top of it here too.
            for method in self._declared_methods(node):
                out.append({
                    "functionId": target,
                    "kind": "http-route",
                    "framework": "flask",
                    "detail": {"method": method, "path": path},
                })
        return out

    @staticmethod
    def _declared_methods(call: ast.Call, default: list[str] | None = None) -> list[str]:
        """The verbs a registration declares, or the framework's default when it declares none.

        Flask defaults to GET when `methods=` is ABSENT. That default was being applied
        even where the argument was present, which recorded every POST-capable route in
        one application as GET-only.
        """
        for kw in call.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                found = [str(e.value).upper() for e in kw.value.elts
                         if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                if found:
                    return list(dict.fromkeys(found))
        return default or ["GET"]

    # --- aiohttp framework model -----------------------------------------
    #
    # aiohttp registers by CALL rather than by decorator, which is why a frontend that
    # knew only decorators and `add_url_rule` enumerated zero routes of an entire
    # application -- and the report still looked complete, because a surface with no
    # entry points reads exactly like a surface with nothing to say. Everything inside
    # those handlers, a SQL injection among it, was invisible.
    _VERB_METHODS = {
        "add_get": "GET", "add_post": "POST", "add_put": "PUT", "add_patch": "PATCH",
        "add_delete": "DELETE", "add_head": "HEAD", "add_view": "ANY",
        "get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE",
        "head": "HEAD", "view": "ANY", "route": "ANY",
    }

    def _router_entry_points(self) -> list[dict]:
        """`app.router.add_route("GET", "/x", views.x)` and the per-verb spellings."""
        out = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            attr = node.func.attr

            if attr == "add_route":
                # add_route(method, path, handler)
                if len(node.args) < 3:
                    continue
                method = self._constant(node.args[0]) or "ANY"
                path = self.path_text(node.args[1])
                handler = node.args[2]
            elif attr in self._VERB_METHODS:
                # add_get(path, handler) and web.get(path, handler). A bare `get` or
                # `post` is only a route when it is given a FUNCTION -- `session.get(key)`
                # and `requests.get(url)` are the same two words and are not routes, which
                # is why the handler has to resolve before anything is recorded.
                if len(node.args) < 2:
                    continue
                method = self._VERB_METHODS[attr]
                path = self.path_text(node.args[0])
                handler = node.args[1]
            else:
                continue

            target = self._function_reference(handler)
            if not target:
                continue
            out.append({
                "functionId": target,
                "kind": "http-route",
                "framework": "aiohttp",
                "detail": {"method": method, "path": path},
            })
        return out

    @staticmethod
    def _constant(node: ast.AST) -> str | None:
        return str(node.value) if isinstance(node, ast.Constant) else None

    def _function_reference(self, node: ast.AST) -> str | None:
        """The function a route registration POINTS AT, named or imported."""
        if isinstance(node, ast.Name):
            return self.global_defs.get(f"{self.module}:{node.id}")
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            # `views.index`, where `views` is a module this file imported.
            module = self.imports.get(node.value.id)
            if module:
                return self.global_defs.get(f"import:{module}.{node.attr}")
            # `Handlers.index` on a class defined here.
            return self.global_defs.get(f"{self.module}:{node.value.id}.{node.attr}")
        return None

    # --- Django URLconf ---------------------------------------------------
    #
    # A frontend that knew Flask, FastAPI and aiohttp enumerated ZERO entry points of a
    # 3,395-function Django application whose source holds 178 route registrations. The
    # largest Python web framework was not modelled at all, and nothing downstream is
    # reachable from a surface that is empty: every finding the engine produced about that
    # application came from a rule that needs no entry point (ADR-009).

    def django_entry_points(self) -> list[dict]:
        """`path("checks/<uuid:code>/", views.details)`, and everything it mounts."""
        owners = self._django_list_owners()
        mounts = self._django_mounts(owners)

        out: list[dict] = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in DJANGO_REGISTRARS or len(node.args) < 2:
                continue
            route = django_route_text(node.args[0])
            if route is None:
                continue
            view = node.args[1]
            # An `include(...)` has no handler of its own: the routes it mounts are
            # registered where they are DEFINED, and they pick this prefix up there.
            if django_included(view) is not None:
                continue
            for prefix in self._django_prefixes_of(owners.get(id(node)), mounts):
                out.extend(self._django_handlers_of(view, django_route_path(prefix + route)))
        return out + self._drf_router_entry_points(mounts)

    def _django_handlers_of(self, view: ast.AST, path: str) -> list[dict]:
        """The functions one registration reaches, and the verb each of them answers."""
        if (isinstance(view, ast.Call) and isinstance(view.func, ast.Attribute)
                and view.func.attr == "as_view"):
            members = self._django_class_members(view.func.value)
            found = [django_entry_point(members[verb], verb.upper(), path)
                     for verb in DJANGO_VERB_METHODS if verb in members]
            if found:
                return found
            hook = self._django_hook(members)
            return [django_entry_point(hook, "ANY", path)] if hook else []

        target = self._function_reference(view)
        # ANY, because a URLconf says nothing about the verb: Django calls the function for
        # every one of them and the function decides for itself, usually by reading
        # `request.method`. Naming a verb here would be inventing one.
        return [django_entry_point(target, "ANY", path)] if target else []

    def _class_key(self, node: ast.AST) -> str | None:
        """The name a class is known by program-wide, out of how a registration wrote it.

        The two spellings `_function_reference` resolves, for the same reason: a
        registration reaches a class either through a module it imported (`views.Detail`)
        or through the class itself (`from hc.front.views import Detail`).
        """
        if isinstance(node, ast.Name):
            imported = self.imports.get(node.id)
            return f"import:{imported}" if imported else f"{self.module}:{node.id}"
        # A chain of any depth, because a registration reaches for one: JupyterHub's
        # catch-all is written `apihandlers.base.API404`, on a package it imported rather
        # than on the module the class is in, and stopping at one attribute left that
        # route -- and every route written the same way -- out of the surface.
        if isinstance(node, ast.Attribute):
            parts: list[str] = []
            cur: ast.AST = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            root = self.imports.get(cur.id) if isinstance(cur, ast.Name) else None
            return ".".join([f"import:{root}", *reversed(parts)]) if root else None
        return None

    def _django_class_members(self, node: ast.AST) -> dict[str, str]:
        """The methods of the class a registration names, wherever it is defined."""
        return self.class_members.get(self._class_key(node) or "", {})

    @staticmethod
    def _django_hook(members: dict[str, str], action: str | None = None) -> str | None:
        """The method a request reaches on a class, when the class names one at all."""
        if action and action in members:
            return members[action]
        for name in DJANGO_HOOKS:
            if name in members:
                return members[name]
        return None

    def _django_list_owners(self) -> dict[int, str]:
        """Which module-level name each registration was written under.

        `urlpatterns` is only the outermost list. An application routinely writes
        `check_urls = [path("log/", views.log)]` and mounts it under a prefix elsewhere in
        the same file, so the list a registration sits IN is what decides the prefix it
        carries -- reading only `urlpatterns` gives every one of those routes the path of
        the file's root instead.
        """
        owners: dict[int, str] = {}
        for stmt in self.tree.body:
            if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)):
                name = stmt.targets[0].id
            elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
                # `urlpatterns += [...]`, which is how a route behind a setting is added.
                name = stmt.target.id
            else:
                continue
            for node in ast.walk(stmt):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id in DJANGO_REGISTRARS):
                    owners.setdefault(id(node), name)
        return owners

    def _django_mounts(self, owners: dict[int, str]) -> dict[str, list[tuple[str, str | None]]]:
        """Local name -> every route it is mounted at, and the list each mount is in.

        `path("checks/<uuid:code>/", include(check_urls))` mounts a list from this file and
        `path("api/", include(router.urls))` mounts a router the same way. Kept as a chain
        rather than as a resolved prefix because the mounting call is routinely written
        above the list it mounts, and a walk cannot depend on the order.

        A list mounted MORE THAN ONCE is served at every one of its mounts, and versioned
        APIs are written exactly that way -- one application mounts a single list of fifteen
        routes at `api/v1/`, `api/v2/` and `api/v3/`, and keeping only the first mount left
        two thirds of a public API out of the surface.
        """
        mounts: dict[str, list[tuple[str, str | None]]] = {}
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in DJANGO_REGISTRARS or len(node.args) < 2:
                continue
            local = django_local_name(django_included(node.args[1]))
            if local is None:
                continue
            mounts.setdefault(local, []).append(
                (django_route_text(node.args[0]) or "", owners.get(id(node))))
        return mounts

    def _django_prefixes_of(self, name: str | None,
                            mounts: dict[str, list[tuple[str, str | None]]]) -> list[str]:
        """Every path a registration is mounted under, from this file and the program.

        A mount that cannot be resolved contributes the empty string rather than dropping
        the route. One application's root URLconf mounts every module of it at a path
        computed from a setting, and this frontend has no evaluator and will never read
        one -- a route at a slightly wrong path is worth a great deal more than a route the
        surface does not contain (ADR-009).

        Bounded, because this is a walk over data: a list that mounts itself terminates on
        the names already seen, and the cap is what stops a URLconf built out of many
        cross-mounted lists from turning one registration into thousands of paths.
        """
        found: list[str] = []
        pending = [(name, "", frozenset())]
        while pending and len(found) < 16:
            name, suffix, seen = pending.pop()
            if name not in mounts or name in seen:
                if suffix not in found:
                    found.append(suffix)
                continue
            for route, parent in mounts[name]:
                pending.append((parent, route + suffix, seen | {name}))
        return [self.django_prefix + prefix for prefix in found]

    def _drf_router_entry_points(self,
                                 mounts: dict[str, list[tuple[str, str | None]]]) -> list[dict]:
        """`router.register("checks", CheckViewSet)` -- six routes written as one line.

        The prefix has to be a STRING and the class has to be one the program defines with
        something that answers a request: `admin.site.register(Check, CheckAdmin)` and
        `signals.register("check-saved", handler)` are the same word and neither is a
        route, while the registration that IS one always names its path.
        """
        out: list[dict] = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "register" or len(node.args) < 2:
                continue
            prefix = django_route_text(node.args[0])
            if prefix is None:
                continue
            members = self._django_class_members(node.args[1])
            if not members:
                continue
            router = node.func.value.id if isinstance(node.func.value, ast.Name) else None
            for mount in self._django_prefixes_of(router, mounts):
                base = mount + prefix.rstrip("/")
                for method, suffix, action in DRF_ROUTES:
                    target = self._django_hook(members, action)
                    if target:
                        out.append(django_entry_point(target, method,
                                                      django_route_path(base + suffix)))
        return out

    # --- Tornado URLSpec --------------------------------------------------
    #
    # Every other registration this frontend knows is a CALL. Tornado's is a tuple in a
    # list, which is not a call and not a decorator and has no name of its own, and a
    # frontend built out of call shapes had nothing to match: JupyterHub enumerated 9
    # entry points against 62 real handler registrations, and all 9 of them came from its
    # `examples/` directory rather than from the application (ADR-009).

    def tornado_entry_points(self) -> list[dict]:
        """`(r"/api/users/([^/]+)", UserAPIHandler)`, and the call spellings of it."""
        out: list[dict] = []
        for node in ast.walk(self.tree):
            spec = self._tornado_spec(node)
            if spec is None:
                continue
            pattern, handler = spec
            out.extend(self._tornado_handlers_of(handler, tornado_route_path(pattern)))
        return out

    def _tornado_spec(self, node: ast.AST) -> tuple[str, ast.AST] | None:
        """The `(pattern, HandlerClass)` of one registration, however it is written.

        Matched by SHAPE and never by the name of the list it sits in: `default_handlers`
        is a convention of Tornado's own documentation and an application is free to build
        its table anywhere -- JupyterHub appends `(r"/logo", LogoHandler, {...})` to a
        local variable inside the method that assembles the application, which is a
        registration exactly as much as the module-level lists are.
        """
        if isinstance(node, ast.Tuple):
            # A third element is the dict of arguments Tornado constructs the handler
            # with, and there is never a fourth. A longer tuple is some other kind of
            # record that happens to begin with a string.
            if not 2 <= len(node.elts) <= 3:
                return None
            if len(node.elts) == 3 and not isinstance(node.elts[2], ast.Dict):
                return None
            parts: list[ast.AST] = node.elts
        elif isinstance(node, ast.Call):
            name = (node.func.id if isinstance(node.func, ast.Name)
                    else getattr(node.func, "attr", ""))
            if name not in TORNADO_REGISTRARS or len(node.args) < 2:
                return None
            parts = node.args
        else:
            return None
        pattern = tornado_pattern_text(parts[0])
        return (pattern, parts[1]) if pattern is not None else None

    def _tornado_handlers_of(self, handler: ast.AST, path: str) -> list[dict]:
        """The methods one registration reaches, and the verb each of them answers.

        Own methods before inherited ones, because that is Python's own resolution order:
        a subclass that names `post` answers POST there and nowhere else.
        """
        members = self._django_class_members(handler)
        # A registered handler is free to define no verb at all and answer entirely in a
        # BASE class in another module. JupyterHub's `/api/(.*)` catch-all is exactly that:
        # `API404` is an empty subclass, and the only method a request there ever reaches
        # is the `options` of the `APIHandler` it extends -- so a lookup that stopped at
        # the class the registration NAMES found nothing to point at.
        #
        # Resolved one level and by the base's own NAME, which is the same looseness the
        # rest of this file's cross-file lookups carry and is stated rather than hidden
        # (ADR-003).
        inherited = self.base_members.get(self._class_key(handler) or "", {})
        if not members and not inherited:
            return []
        for source in (members, inherited):
            found = [tornado_entry_point(source[verb], verb.upper(), path)
                     for verb in TORNADO_VERB_METHODS if verb in source]
            if found:
                return found
        for source in (members, inherited):
            for hook in TORNADO_HOOKS:
                if hook in source:
                    return [tornado_entry_point(source[hook], "ANY", path)]
        # The base is in a package this program does not contain -- Tornado's own
        # RequestHandler, or a mixin from a library -- and the route is real all the same.
        # The class's first method stands in for the verb: an entry point at a slightly
        # imprecise function is worth far more than one that does not exist, and dropping
        # the route would put the whole class outside the surface (ADR-009).
        first = next(iter(members.values()), None) or next(iter(inherited.values()))
        return [tornado_entry_point(first, "ANY", path)]

    # --- Flask framework model -------------------------------------------
    #
    # Isolated here for the same reason the Express model is isolated in the
    # TypeScript frontend (ADR-004): framework knowledge is data about a
    # framework, not a property of the language.

    def entry_points_for(self, node: ast.AST, function_id: str) -> list[dict]:
        out = []
        for dec in getattr(node, "decorator_list", []):
            out.extend(self._entry_points_for_decorator(dec, function_id))
        return out

    def _entry_points_for_decorator(self, dec: ast.AST, function_id: str) -> list[dict]:
        """Every entry point one route decorator registers.

        EVERY one, because `methods=["GET", "POST"]` is one decorator and two entry
        points. Reporting only the first left every POST-capable Flask route in a search
        engine's web application labelled GET-only, which is the exact fact a body-based
        bypass of a query-string-only guard turns on: with the verb wrong, the question
        cannot even be asked.
        """
        if not isinstance(dec, ast.Call):
            return []

        # `@app.route(...)`, `@router.get(...)` — bound to an object, and the OBJECT is
        # what says which framework this is. Reading it off the file's imports made
        # `@router.get` on a FastAPI `APIRouter` report as flask whenever anything else
        # in the file was Flask-shaped.
        if isinstance(dec.func, ast.Attribute):
            attr = dec.func.attr
            receiver = dec.func.value
            known_binder = (isinstance(receiver, ast.Name)
                            and receiver.id in self.binder_framework)
            framework = (self.binder_framework[receiver.id] if known_binder
                         else self._framework_by_import(attr))
        # `@expose("/path")` — a bare name, which is how Flask-AppBuilder and
        # several other view frameworks register. Requiring an attribute made
        # every such route invisible.
        elif isinstance(dec.func, ast.Name):
            # A BARE name is a route only for the frameworks that register that way.
            # Accepting every verb here read `@patch("module.thing")` -- unittest's
            # mock decorator -- as an HTTP route, and one application reported 1338
            # routes where it has about 1025. A surface that invents entry points is
            # worse than one that misses them: it is the primary output, and every
            # judgement rests on it (ADR-009).
            attr = dec.func.id
            if attr != "expose":
                return []
            receiver, known_binder = None, False
            framework = "flask-appbuilder"
        else:
            return []

        # An error handler is reached by making a request that fails, which is
        # something any caller can do on purpose. It reads the request object like
        # any other handler, and a vulnerable Flask application interpolates
        # `request.url` into a template inside one. Treating it as unreachable left
        # a real template injection in the unanchored section, where nothing gates.
        if attr == "errorhandler":
            return [{
                "functionId": function_id,
                "kind": "http-route",
                "framework": framework,
                "detail": {"method": "ANY", "path": "<error handler>"},
            }]

        if attr not in ("route", "expose", "get", "post", "put", "patch", "delete"):
            return []

        path = self.path_text(dec.args[0]) if dec.args else unresolved_path()
        # A verb decorator whose first argument is not a PATH is not a route.
        # `@mock.patch("sqli.dao.user.User")` and `@pytest.mark.parametrize(...)` are
        # written the same way and mean something else entirely. A receiver this file
        # WATCHED being constructed as a router is exempt: `@router.get(PREFIX)` is a
        # route on the evidence of the binding, whatever the argument resolves to.
        if attr not in ("route", "expose") and not known_binder and not path.startswith("/"):
            return []

        path = join_route(self.binder_prefix_text(receiver) if receiver is not None else "",
                          path)

        # A verb decorator names its own verb; `route` and `expose` fall back on Flask's
        # GET default, and only where `methods=` is absent.
        methods = self._declared_methods(
            dec, ["GET"] if attr in ("route", "expose") else [attr.upper()])

        return [{
            "functionId": function_id,
            "kind": "http-route",
            "framework": framework,
            "detail": {"method": method, "path": path},
        } for method in methods]

    def _framework_by_import(self, attr: str) -> str:
        """The framework of a receiver this file never watched being constructed.

        A handler routinely takes its router as a PARAMETER (`def register(router):`), so
        the binding is in another file. The DECORATOR still narrows it: `.route(...)` is
        Flask's spelling and FastAPI has no such decorator, so only a bare verb is
        ambiguous -- and there the file's imports are the next best evidence. Flask stays
        the answer when there is none, which is what this used to say unconditionally.
        """
        if attr in ("route", "expose", "errorhandler"):
            return "flask"
        roots = {origin.split(".")[0] for origin in self.imports.values()}
        for module, framework in ROUTER_MODULE_FRAMEWORKS:
            if module in roots and framework != "flask":
                return framework
        return "flask"


class FunctionLowerer:
    def __init__(self, mod: ModuleLowerer, node: ast.AST):
        self.mod = mod
        self.node = node
        self.is_module = isinstance(node, ast.Module)
        self.name = "<module>" if self.is_module else getattr(node, "name", "<lambda>")
        lineno = 0 if self.is_module else node.lineno
        col = 0 if self.is_module else getattr(node, "col_offset", 0) + 1
        # The COLUMN is part of the identity, not decoration: two lambdas on one line
        # collide without it, and a colliding id means one function's body is attributed
        # to the other.
        self.id = f"{mod.module}#{self.name}:{lineno}:{col}"
        self.enclosing_class = mod.class_of.get(id(node))
        self.values: list[dict] = []
        self.flows: list[dict] = []
        self.calls: list[dict] = []
        self.returns: list[str] = []
        self.comparisons: list[dict] = []
        self.writes: list[dict] = []
        self.blocks: list[dict] = []
        self._b = 0
        # Depth inside statements the block graph does not model; see
        # UNMODELLED_STATEMENTS and `add_flow`.
        self.unmodelled = 0
        self.entry_block = self.new_block(node)
        self.current = self.entry_block
        self.params: list[dict] = []
        self.scope: dict[str, str] = {}
        self.prop_cache: dict[str, str] = {}
        self.local_types: dict[str, str] = {}
        self.globals_seen: dict[str, str] = {}
        # Names this function declared global or nonlocal, which is what makes an
        # assignment to one a write to state outside it.
        self.declared_global: set[str] = set()
        self._v = 0
        self._c = 0

    def new_block(self, node: ast.AST) -> str:
        bid = f"{self.id}$b{self._b}"
        self._b += 1
        self.blocks.append(
            {"id": bid, "successors": [], "loc": loc_of(self.mod.module, node)}
        )
        return bid

    def block_at(self, bid: str) -> dict | None:
        return next((b for b in self.blocks if b["id"] == bid), None)

    def link(self, src: str, dst: str) -> None:
        block = self.block_at(src)
        if block is not None and dst not in block["successors"]:
            block["successors"].append(dst)

    def terminate(self, bid: str, kind: str) -> None:
        block = self.block_at(bid)
        if block is not None:
            block["terminator"] = kind

    def leaves(self, bid: str) -> bool:
        block = self.block_at(bid)
        return bool(block) and block.get("terminator") in ("return", "throw")

    def new_value(self, kind: str, node: ast.AST, **extra: Any) -> str:
        vid = f"{self.id}$v{self._v}"
        self._v += 1
        value = {"id": vid, "kind": kind, "loc": loc_of(self.mod.module, node)}
        value.update({k: v for k, v in extra.items() if v is not None})
        self.values.append(value)
        return vid

    def add_flow(self, src: str | None, dst: str, kind: str, node: ast.AST) -> None:
        if src and dst:
            flow = {"from": src, "to": dst, "kind": kind, "loc": loc_of(self.mod.module, node)}
            # The block is stated only where the block graph expresses when the edge
            # runs. See `UNMODELLED_STATEMENTS`: an absent block is a refusal, and the
            # core keeps the flow rather than reasoning about a position nobody vouched
            # for (ADR-003).
            if not self.unmodelled:
                flow["block"] = self.current
            self.flows.append(flow)

    def write_block(self) -> str | None:
        """Where a write sits in the block graph, on the same terms as a flow.

        A loop body and a `match` arm are positions the graph does not express, so the
        frontend states none and a judgement that needs one declines to be made.
        """
        return None if self.unmodelled else self.current

    def lower(self) -> dict:
        # A module's top level is code like any other, and it is where configuration
        # lives: `app.run(debug=True)` is never inside a function. Lowering it as a
        # function of its own lets every analysis kind see it without learning a new
        # shape. The statement walk already stops at function boundaries.
        if self.is_module:
            for stmt in self.node.body:
                self.walk(stmt)
            return self._result()

        for index, arg in enumerate(self.node.args.args):
            vid = self.new_value("param", arg, name=arg.arg)
            self.scope[arg.arg] = vid
            self.params.append({"index": index, "name": arg.arg, "valueId": vid})
            # An annotation is the author stating the type outright, which is the
            # strongest thing this frontend will ever have.
            self.note_local_type(arg, arg.annotation, None, name=arg.arg)

        # `**kwargs` is a dict and `*args` is a tuple, always, by the language's own
        # rules — no annotation or inference required.
        if self.node.args.kwarg:
            self.local_types[self.node.args.kwarg.arg] = "dict"
        if self.node.args.vararg:
            self.local_types[self.node.args.vararg.arg] = "tuple"

        for stmt in self.node.body:
            self.walk(stmt)

        return self._result()

    def _result(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "module": self.mod.module,
            "loc": loc_of(self.mod.module, self.node) if not self.is_module else {"file": self.mod.module, "line": 1, "column": 1},
            "params": self.params,
            "values": self.values,
            "flows": self.flows,
            "calls": self.calls,
            "returns": self.returns,
            "comparisons": self.comparisons,
            "writes": [{k: v for k, v in w.items() if v is not None} for w in self.writes],
            "entryBlock": self.entry_block,
            "blocks": self.blocks,
        }

    def walk(self, node: ast.AST) -> None:
        # A loop runs its body an unknown number of times and `try`/`match` choose
        # between arms, and the block graph says none of it: all of them are lowered
        # straight-line into the enclosing block. The walk is unchanged; what is
        # suppressed is the CLAIM that a flow inside one of them sits at a known point in
        # the control-flow graph, which the core would otherwise read as licence to kill
        # an earlier definition of the same name.
        if isinstance(node, UNMODELLED_STATEMENTS):
            self.unmodelled += 1
            try:
                self._walk(node)
            finally:
                self.unmodelled -= 1
            return
        self._walk(node)

    def _walk(self, node: ast.AST) -> None:
        # Nested functions are separate IR functions; their bodies are not inlined.
        if isinstance(node, FUNCTION_NODES) and node is not self.node:
            return

        if isinstance(node, ast.Assign):
            src = self.expr(node.value)
            for target in node.targets:
                # An assignment INTO something: `session["user"] = x`, `cfg.debug = y`.
                # Only plain names were lowered, so writing into an attribute or a
                # subscript recorded nothing -- and putting caller data into a session is
                # a weakness whose entire shape is the write.
                if isinstance(target, ast.Attribute):
                    self.writes.append({
                        "loc": loc_of(self.mod.module, node),
                        "base": self.expr(target.value),
                        "path": target.attr,
                        "from": src,
                        "block": self.write_block(),
                    })
                    continue
                if isinstance(target, ast.Subscript):
                    key = target.slice
                    literal_key = isinstance(key, ast.Constant) and isinstance(key.value, str)
                    # A COMPUTED key is recorded as a value, because how many entries a
                    # container can come to hold is decided by how many distinct keys
                    # reach it -- and a key the caller chose has no ceiling. A literal
                    # key is an attribute name spelled differently and goes in `path`
                    # with every other fixed name.
                    self.writes.append({
                        "loc": loc_of(self.mod.module, node),
                        "base": self.expr(target.value),
                        "path": key.value if literal_key else None,
                        "key": None if literal_key else self.expr(key),
                        "from": src,
                        "block": self.write_block(),
                    })
                    continue
                if isinstance(target, (ast.Tuple, ast.List)):
                    # `requestor_id, brand, software_statement = self._DOMAIN_MAP[domain]`
                    # bound three names and lowered NOTHING: an unpacking target matched
                    # no branch here, so the names did not exist as values and no rule
                    # could follow what was put in them. Every judgement about where a
                    # destructured value goes was silently unanswerable -- four Adobe
                    # client attestations in yt-dlp were reported as this program's
                    # secrets for that reason and no other.
                    #
                    # Each name gets the right-hand side, which is what unpacking means:
                    # every element came out of the one object. A nested target and a
                    # starred one bind names too, and only the plain names are taken --
                    # what is skipped is skipped visibly rather than guessed at.
                    for elt in target.elts:
                        if isinstance(elt, ast.Starred):
                            elt = elt.value
                        if not isinstance(elt, ast.Name):
                            continue
                        vid = self.new_value("local", elt, name=elt.id)
                        self.scope[elt.id] = vid
                        if self.is_module:
                            self.mod.module_scope[elt.id] = vid
                        self.add_flow(src, vid, "element", node)
                    continue
                if isinstance(target, ast.Name):
                    # Assigning a name a function DECLARED global writes state the whole
                    # process shares, and the next request reads it back. Python makes
                    # this unambiguous: without the declaration the same statement makes a
                    # local and touches nothing outside, so the declaration is the entire
                    # evidence and there is no guessing.
                    if not self.is_module and target.id in self.declared_global:
                        self.writes.append({
                            "loc": loc_of(self.mod.module, node),
                            "base": self.mod.module_scope.get(target.id),
                            "path": target.id,
                            "from": src,
                            "block": self.write_block(),
                            "scope": "process",
                        })
                    vid = self.new_value("local", target, name=target.id)
                    self.scope[target.id] = vid
                    if self.is_module:
                        self.mod.module_scope[target.id] = vid
                    self.add_flow(src, vid, "assign", node)
                    self.note_local_type(target, None, node.value)
            return

        # `with open(path) as fh:` is how Python opens anything, and the call sat in a
        # place the statement walk never reached: the context expression is not a
        # statement, so the generic recursion walked past it into its children and the
        # call was never lowered at all. Every rule about what a program opens, connects
        # to or unpacks was blind to the spelling the language recommends.
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                src = self.expr(item.context_expr)
                target = item.optional_vars
                if isinstance(target, ast.Name):
                    vid = self.new_value("local", node, name=target.id)
                    self.scope[target.id] = vid
                    if self.is_module:
                        self.mod.module_scope[target.id] = vid
                    self.add_flow(src, vid, "assign", node)
            for stmt in node.body:
                self.walk(stmt)
            return

        # `for entry in archive.namelist():` binds a name to an ELEMENT of something, and
        # the collection is the whole evidence for what the element is. Without this the
        # chain simply stopped at the loop: a list of objects a caller sent produced
        # elements related to nothing, and every judgement about what the loop did with
        # them was silent.
        #
        # The flow kind is "property" rather than "enclose" because that is the direction
        # it goes -- an element comes OUT of the collection, and it comes out whole.
        if isinstance(node, (ast.For, ast.AsyncFor)):
            src = self.expr(node.iter)
            # Destructuring nests: `for [name, [path, mode]] in request.json` binds three
            # names, and reading only the immediate children found one of them.
            for target in _bound_names(node.target):
                vid = self.new_value("local", target, name=target.id)
                self.scope[target.id] = vid
                if self.is_module:
                    self.mod.module_scope[target.id] = vid
                self.add_flow(src, vid, "property", node)
            for stmt in list(node.body) + list(node.orelse):
                self.walk(stmt)
            return

        if isinstance(node, (ast.Global, ast.Nonlocal)):
            self.declared_global.update(node.names)
            return

        if isinstance(node, ast.AnnAssign):
            src = self.expr(node.value) if node.value else None
            if isinstance(node.target, ast.Name):
                vid = self.new_value("local", node.target, name=node.target.id)
                self.scope[node.target.id] = vid
                self.add_flow(src, vid, "assign", node)
                self.note_local_type(node.target, node.annotation, node.value)
            return

        if isinstance(node, ast.Return):
            if node.value is not None:
                vid = self.expr(node.value)
                if vid:
                    self.returns.append(vid)
            self.terminate(self.current, "return")
            self.current = self.new_block(node)
            return

        if isinstance(node, ast.Raise):
            if node.exc is not None:
                self.expr(node.exc)
            self.terminate(self.current, "throw")
            self.current = self.new_block(node)
            return

        if isinstance(node, ast.Expr):
            self.expr(node.value)
            return

        # Conditions are not statements and are never reached on their own. The test
        # belongs to the block that branches on it.
        if isinstance(node, ast.If):
            self.expr(node.test)
            branch = self.current
            self.terminate(branch, "branch")

            then_block = self.new_block(node)
            self.link(branch, then_block)
            self.current = then_block
            for stmt in node.body:
                self.walk(stmt)
            then_end = self.current

            else_end = None
            if node.orelse:
                else_block = self.new_block(node)
                self.link(branch, else_block)
                self.current = else_block
                for stmt in node.orelse:
                    self.walk(stmt)
                else_end = self.current

            after = self.new_block(node)
            if not self.leaves(then_end):
                self.link(then_end, after)
            if else_end is None:
                self.link(branch, after)
            elif not self.leaves(else_end):
                self.link(else_end, after)

            self.current = after
            return

        # An except binding is where internal failure detail enters the program.
        if isinstance(node, ast.ExceptHandler):
            if node.name:
                vid = self.new_value("catch-param", node, name=node.name)
                self.scope[node.name] = vid
            for stmt in node.body:
                self.walk(stmt)
            return

        for child in ast.iter_child_nodes(node):
            self.walk(child)

    # --- expressions ------------------------------------------------------

    def path_of(self, vid: str) -> str:
        """The access path already recorded for a value, or empty."""
        for v in self.values:
            if v["id"] == vid:
                return v.get("path") or ""
        return ""

    def expr(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Await):
            return self.expr(node.value)

        if isinstance(node, ast.Name):
            if node.id in self.scope:
                return self.scope[node.id]
            # A name this function never bound, bound at module level. Values are
            # identified globally, so referring to one from another function is
            # ordinary.
            if not self.is_module and node.id in self.mod.module_scope:
                return self.mod.module_scope[node.id]
            symbol = self.mod.imports.get(node.id)
            if symbol:
                # A framework-bound global (flask.request) is a value like any
                # other, so property access on it works the same way it does on a
                # parameter.
                if node.id not in self.globals_seen:
                    self.globals_seen[node.id] = self.new_value(
                        "global", node, name=symbol
                    )
                return self.globals_seen[node.id]
            return None

        if isinstance(node, ast.Attribute):
            return self.attribute(node)

        if isinstance(node, ast.Call):
            return self.call(node)

        if isinstance(node, ast.Subscript):
            # `request.args["login"]`, `rows[0]`, `payload[key]`. Reading out of a value
            # carries whatever was in it, exactly as an attribute read does: the index
            # chooses WHICH part, not whether the part is trusted.
            #
            # Flask exposes the request as a mapping, so almost every untrusted value in
            # a Flask application arrives through a subscript. Without this the taint
            # stopped at the very first hop and the framework was effectively unmodelled.
            base = self.expr(node.value)
            if not base:
                return None
            # A LITERAL key is a property name written differently. `form["password"]`
            # and `form.password` are the same access, and recording the first as an
            # anonymous index threw away the only part that says what the field IS --
            # which is what every rule keyed on a path leaf reads. Flask exposes the
            # request as a mapping, so that was every credential rule blind on Flask.
            key = node.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                base_path = self.path_of(base)
                path = f"{base_path}.{key.value}" if base_path else key.value
                vid = self.new_value("property", node, name=key.value, base=base, path=path)
                self.add_flow(base, vid, "property", node)
                return vid
            vid = self.new_value("property", node, name="[index]", base=base)
            self.add_flow(base, vid, "property", node)
            return vid

        if isinstance(node, ast.JoinedStr):
            vid = self.new_value("local", node, name="f-string")
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    self.add_flow(self.expr(part.value), vid, "template", node)
                # The STATIC text of an f-string is a value too. Dropping it lost the half
                # of the string the PROGRAM wrote, so a rule that asks what a composed
                # value says -- does this statement contain a SQL verb -- could answer for
                # `"SELECT ..." % x` and not for the same statement written as an f-string.
                elif isinstance(part, ast.Constant) and isinstance(part.value, str) and part.value:
                    lit = self.new_value("literal", node, literal=part.value)
                    self.add_flow(lit, vid, "template", node)
            return vid

        # `+` and `%` are both string composition in Python, and `%` is the older and
        # more common of the two for building SQL. Handling only `+` broke the chain at
        # the exact idiom the language is most often injected through: a documented SQL
        # injection in a deliberately vulnerable application is written
        # `"... WHERE username = '%s';" % search_term`, and it was invisible.
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            vid = self.new_value("local", node, name="concat")
            self.add_flow(self.expr(node.left), vid, "binary", node)
            self.add_flow(self.expr(node.right), vid, "binary", node)
            return vid

        # A relational test is a fact in its own right.
        # `not x` produces a boolean, so nothing flows out of it -- but its OPERAND still
        # has to be lowered, because that is where the calls are. `if not PATTERN.match(
        # value):` is how a great deal of validation is written, and falling through here
        # meant the call was never in the IR at all: no rule could see an operation the
        # program plainly performs.
        if isinstance(node, ast.UnaryOp):
            inner = self.expr(node.operand)
            # `not x` produces a boolean unrelated to what it was given. `+x` and `-x`
            # are numeric and the MAGNITUDE survives, which is the part a rule about a
            # bound or a seed cares about.
            if isinstance(node.op, (ast.UAdd, ast.USub)):
                return inner
            return None

        if isinstance(node, ast.Compare):
            left = self.expr(node.left)
            vid = self.new_value("local", node, name="comparison")
            for op, comparator in zip(node.ops, node.comparators):
                right = self.expr(comparator)
                if left and right:
                    self.comparisons.append(
                        {
                            "left": left,
                            "right": right,
                            "op": type(op).__name__,
                            "block": self.current,
                            "loc": loc_of(self.mod.module, node),
                        }
                    )
            return vid

        if isinstance(node, ast.Dict):
            vid = self.new_value("local", node, name="{dict}")
            for key, value in zip(node.keys, node.values):
                # A dict's keys are not reliably configuration names -- a lookup table
                # from a setting to its group has the same shape and its keys are data.
                # Python's configuration is written as assignment (`app.config["X"] =`),
                # which is already recorded, so nothing is lost by declining this here.
                # `{**request.json}` is not an enclosure. A double-star has no key, and
                # every key the value HAD is still a key here -- which is exactly what a
                # rule asking "did this arrive whole" wants to know. Calling it an
                # enclosure said the application had chosen the fields when it had chosen
                # none of them.
                kind = "enclose" if key is not None else "assign"
                self.add_flow(self.expr(value), vid, kind, node)
            return vid

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            vid = self.new_value("local", node, name="[sequence]")
            for element in node.elts:
                self.add_flow(self.expr(element), vid, "enclose", node)
            return vid

        # `request.args.get("next") or "/"` is how Python writes a default, and the
        # value that survives it is the caller's whenever one was sent. The flow kind is
        # "assign" rather than "binary" on purpose: choosing between two values is not
        # composing text out of them, and calling it composition would make
        # `execute(request.args["q"] or "")` look like a built statement.
        if isinstance(node, ast.BoolOp):
            vid = self.new_value("local", node, name="either")
            for value in node.values:
                self.add_flow(self.expr(value), vid, "assign", node)
            return vid

        # The walrus binds and carries at the same time.
        if isinstance(node, ast.NamedExpr):
            src = self.expr(node.value)
            if isinstance(node.target, ast.Name):
                vid = self.new_value("local", node.target, name=node.target.id)
                self.scope[node.target.id] = vid
                self.add_flow(src, vid, "assign", node)
                return vid
            return src

        # A comprehension produces a collection out of an iterable, and the element
        # expression is where the values come from. `[row["name"] for row in
        # request.json]` was falling through, so a list built out of a caller's data was
        # related to nothing -- and building a list out of a request body is what a bulk
        # endpoint does.
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            name = "{comprehension}" if isinstance(node, ast.DictComp) else "[comprehension]"
            vid = self.new_value("local", node, name=name)
            # A comprehension has its OWN scope in Python 3. Binding its variable in the
            # enclosing one and leaving it there would make `x = request.args["cmd"]; [x
            # for x in ["safe"]]; os.system(x)` resolve the last `x` to the loop variable
            # and lose the injection, which is the opposite of what the language does.
            shadowed = {}
            for gen in node.generators:
                src = self.expr(gen.iter)
                if isinstance(gen.target, ast.Name):
                    key = gen.target.id
                    if key not in shadowed:
                        shadowed[key] = self.scope.get(key)
                    tid = self.new_value("local", gen.target, name=key)
                    self.scope[key] = tid
                    self.add_flow(src, tid, "property", node)
                # The filters are part of the comprehension and hold calls of their own.
                for test in gen.ifs:
                    self.expr(test)
            if isinstance(node, ast.DictComp):
                self.add_flow(self.expr(node.key), vid, "enclose", node)
                self.add_flow(self.expr(node.value), vid, "enclose", node)
            else:
                self.add_flow(self.expr(node.elt), vid, "enclose", node)
            for key, previous in shadowed.items():
                if previous is None:
                    self.scope.pop(key, None)
                else:
                    self.scope[key] = previous
            return vid

        if isinstance(node, ast.Starred):
            return self.expr(node.value)

        if isinstance(node, ast.IfExp):
            vid = self.new_value("local", node, name="conditional")
            self.add_flow(self.expr(node.body), vid, "assign", node)
            self.add_flow(self.expr(node.orelse), vid, "assign", node)
            return vid

        if isinstance(node, ast.Constant):
            return self.new_value("literal", node, literal=constant_text(node.value))

        return None

    def attribute(self, node: ast.Attribute) -> str | None:
        segments: list[str] = []
        cur: ast.AST = node
        while isinstance(cur, ast.Attribute):
            segments.insert(0, cur.attr)
            cur = cur.value

        base = self.expr(cur) if isinstance(cur, ast.Name) else None
        if not base:
            return None

        dotted = ".".join(segments)
        key = f"{base}|{dotted}"
        if key in self.prop_cache:
            return self.prop_cache[key]

        vid = self.new_value("property", node, base=base, path=dotted, name=dotted)
        self.add_flow(base, vid, "property", node)
        self.prop_cache[key] = vid
        return vid

    def local_type_of(self, node: ast.AST) -> str | None:
        """The receiver's type, when this function said what it is.

        Two sources, both local and both explicit: an annotation the author wrote
        (`form_data: dict[str, Any] = {}`) and a literal this function assigned
        (`payload = {}`). Anything reaching the function from elsewhere is unknown, and
        stays unknown — guessing here would be worse than the ambiguity it resolves.
        """
        if not isinstance(node, ast.Name):
            return None
        return self.local_types.get(node.id)

    def note_local_type(
        self,
        target: ast.AST,
        annotation: ast.AST | None,
        value: ast.AST | None,
        name: str | None = None,
    ) -> None:
        if name is None:
            if not isinstance(target, ast.Name):
                return
            name = target.id
        if annotation is not None:
            base = annotation
            if isinstance(base, ast.Subscript):
                base = base.value
            if isinstance(base, ast.Name):
                self.local_types[name] = base.id
                return
            if isinstance(base, ast.Attribute):
                self.local_types[name] = base.attr
                return
        if isinstance(value, ast.Dict):
            self.local_types[name] = "dict"
        elif isinstance(value, (ast.List, ast.ListComp)):
            self.local_types[name] = "list"
        elif isinstance(value, (ast.Set, ast.SetComp)):
            self.local_types[name] = "set"
        elif isinstance(value, ast.DictComp):
            self.local_types[name] = "dict"
        elif isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            if value.func.id in BUILTIN_CONTAINERS:
                self.local_types[name] = value.func.id
        elif (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "copy"
            and isinstance(value.func.value, ast.Name)
        ):
            # A container's copy is the same kind of container.
            source = self.local_types.get(value.func.value.id)
            if source in BUILTIN_CONTAINERS:
                self.local_types[name] = source

    @staticmethod
    def _literal_of(node: ast.AST) -> str | None:
        """An argument written as a literal, for defects visible in the call itself.

        `hashlib.md5()` and `requests.get(url, verify=False)` are defects with no dataflow
        anywhere near them, and there is no way to say so without the value.
        """
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                return "true" if node.value else "false"
            if node.value is None:
                return "null"
            if isinstance(node.value, (str, int, float)):
                return str(node.value)
        return None

    def call(self, node: ast.Call) -> str:
        args = []
        literals: dict[int, str] = {}
        for index, arg in enumerate(node.args):
            vid = self.expr(arg)
            if vid:
                args.append({"index": index, "valueId": vid})
            lit = self._literal_of(arg)
            if lit is not None:
                literals[index] = lit
        # `**opts` hides which keywords the call actually passes, so after one the key
        # set is no longer knowable. Recorded, because "does not set httponly" and
        # "cannot see what it sets" are different claims and only one of them is safe
        # to report.
        keys_known = True
        # Nested option keys are numbered below every top-level one, so the two never
        # collide however many of each a call has.
        nested = -1000
        # What each keyword carries. A template reads its values by NAME, so linking a
        # render call to the view it renders needs this map and nothing else.
        by_keyword: dict[str, str] = {}
        for offset, kw in enumerate(node.keywords):
            vid = self.expr(kw.value)
            if vid:
                args.append({"index": len(node.args), "valueId": vid})
                if kw.arg:
                    by_keyword[kw.arg] = vid
            if not kw.arg:
                keys_known = False
                continue
            # A keyword argument's literal is recorded under its NAME rather than a
            # position, because `verify=False` means the same thing wherever it is written.
            lit = self._literal_of(kw.value)
            literals[-(offset + 1)] = f"{kw.arg}={lit if lit is not None else '?'}"

            # One level down. An option that decides something is routinely written
            # inside a named group -- `ssl={"verify": False}`, `options={"debug": True}`
            # -- and reading only the top level recorded the group as present with an
            # unknown value while the decision sat inside it. The key keeps its parent so
            # the nesting stays visible; matching compares the last segment.
            if isinstance(kw.value, ast.Dict):
                for ik, iv in zip(kw.value.keys, kw.value.values):
                    if not isinstance(ik, ast.Constant) or not isinstance(ik.value, str):
                        continue
                    ilit = self._literal_of(iv)
                    nested -= 1
                    literals[nested] = f"{kw.arg}.{ik.value}={ilit if ilit is not None else '?'}"

        method = None
        receiver = None
        receiver_type = None
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            receiver = self.expr(node.func.value)
            receiver_type = self.local_type_of(node.func.value)

        callee = self.resolve_callee(node)
        result = self.new_value(
            "call-result", node, name=callee.get("symbol") or callee["kind"]
        )

        call = {
            "id": f"{self.id}$c{self._c}",
            "loc": loc_of(self.mod.module, node),
            "callee": callee,
            "args": args,
            "resultValueId": result,
            "block": self.current,
        }
        self._c += 1
        if method:
            call["method"] = method
        written = len(node.args) + len(node.keywords)
        if written:
            call["argCount"] = written
        if literals:
            call["argLiterals"] = {str(k): v for k, v in literals.items()}
        if keys_known:
            # -1 denotes the keyword arguments taken as a group, which is where a
            # Python call keeps the options an object literal holds in JavaScript.
            call["enumeratedOptions"] = [-1]
        if receiver_type:
            call["receiverType"] = receiver_type
            if receiver_type in BUILTIN_CONTAINERS:
                call["receiverTypeOrigin"] = "builtin"

        if receiver:
            call["receiverValueId"] = receiver
        self.calls.append(call)

        # Exactly `render_template`. `render_template_string` takes the template SOURCE
        # rather than a name, and is a different weakness with its own rule (CWE-1336).
        if (callee.get("symbol") or "").rsplit(".", 1)[-1] == "render_template":
            self.lower_rendered_template(node, by_keyword)
        return result

    def lower_rendered_template(self, node: ast.Call, by_keyword: dict[str, str]) -> None:
        """Where a render call ends and a view begins.

        `render_template("page.html", name=x)` hands a set of named values to a file this
        frontend has already read, and that file decides which of them are escaped. The
        two halves are joined here rather than by making the template a function the call
        targets: a view's parameters are its variable names rather than positions, and the
        mapping from keywords to those names is the whole of the link.

        The interpolation becomes a call at the TEMPLATE's location, so a finding points
        at the line that writes the page rather than at the handler that asked for it.
        Both escaped and unescaped reads are recorded, because escaping settles cross-site
        scripting and settles nothing about a password rendered into a page.

        Silent when the view name is not written in the call, when two templates could
        answer to it, or when the context was built elsewhere and spread in -- each is a
        case where naming a file would mean guessing which one (ADR-003).
        """
        if not node.args or not isinstance(node.args[0], ast.Constant):
            return
        name = node.args[0].value
        if not isinstance(name, str):
            return
        view = resolve_template(self.mod.templates, name)
        if view is None or not view.reads:
            return

        for read in view.reads:
            root, _, rest = read["path"].partition(".")
            src = by_keyword.get(root)
            if not src:
                continue
            at = {"file": view.module, "line": read["line"], "column": read["column"]}
            value_id = src
            if rest:
                # The path BELOW the root is a read out of the value the handler passed,
                # and every rule that asks what a field is called reads it this way.
                value_id = f"{self.id}$v{self._v}"
                self._v += 1
                self.values.append(
                    {"id": value_id, "kind": "property", "loc": at, "base": src,
                     "path": rest, "name": rest}
                )
                self.flows.append({"from": src, "to": value_id, "kind": "property",
                                   "loc": at, "block": self.current})
            symbol = "<template>.escaped" if read["escaped"] else "<template>.unescaped"
            result_id = f"{self.id}$v{self._v}"
            self._v += 1
            self.values.append({"id": result_id, "kind": "call-result", "loc": at, "name": symbol})
            self.calls.append({
                "id": f"{self.id}$c{self._c}",
                "loc": at,
                "callee": {"kind": "external", "symbol": symbol, "resolution": "resolved"},
                "args": [{"index": 0, "valueId": value_id}],
                "argCount": 1,
                "resultValueId": result_id,
                "block": self.current,
            })
            self._c += 1

    def resolve_callee(self, node: ast.Call) -> dict:
        func = node.func

        if isinstance(func, ast.Name):
            local = self.mod.global_defs.get(f"{self.mod.module}:{func.id}")
            if local:
                return {"kind": "local", "functionId": local, "resolution": "resolved"}
            imported = self.mod.imports.get(func.id)
            if imported:
                target = self.mod.global_defs.get(f"import:{imported}")
                if target:
                    return {"kind": "local", "functionId": target, "resolution": "resolved"}
                return {"kind": "external", "symbol": imported, "resolution": "resolved"}
            # A name that is neither defined here nor imported is the language's own.
            # Qualifying it is what lets a rule be written against `builtins.open` rather
            # than against the bare word -- and the bare word was what the frontend
            # emitted, so every rule about what Python OPENS matched nothing at all.
            # `open` is the most common file API in the language.
            if func.id in PYTHON_BUILTINS:
                return {"kind": "external", "symbol": f"builtins.{func.id}", "resolution": "resolved"}
            return {"kind": "external", "symbol": func.id, "resolution": "probable"}

        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            # `self.helper()` inside a class resolves to that class's own method.
            # Inheritance and rebinding can still defeat this, so the resolution is
            # PROBABLE rather than resolved — which costs confidence at the sink
            # instead of pretending the edge is certain (ADR-005).
            if func.value.id in ("self", "cls") and self.enclosing_class:
                target = self.mod.global_defs.get(
                    f"{self.mod.module}:{self.enclosing_class}.{func.attr}"
                )
                if target:
                    return {"kind": "local", "functionId": target, "resolution": "probable"}

            root = self.mod.imports.get(func.value.id)
            if root:
                # An imported CLASS's method, which is how a data-access layer is
                # written: `from sqli.dao.student import Student` and then
                # `Student.create(conn, name)`. Resolving only module-level functions
                # left every such call external, so a tainted argument tainted the
                # RESULT instead of entering the method -- and a SQL injection two files
                # away was invisible.
                target = self.mod.global_defs.get(f"import:{root}.{func.attr}")
                if target:
                    return {"kind": "local", "functionId": target, "resolution": "resolved"}
                return {
                    "kind": "external",
                    "symbol": f"{root}.{func.attr}",
                    "resolution": "resolved",
                }
            return {
                "kind": "external",
                "symbol": f"{func.value.id}.{func.attr}",
                "resolution": "probable",
            }

        # A chain of attributes: `db.engine.execute(...)`, `self.db.session.execute(...)`,
        # `app.config.get(...)`. Only a one-level `a.b()` was handled, so anything deeper
        # fell through to unresolved -- which is a hole rather than a judgement, and it
        # cost every such sink its confidence. A vulnerable Flask application's SQL
        # injection read LOW for no reason except the number of dots in front of it.
        if isinstance(func, ast.Attribute):
            parts: list[str] = []
            cur: ast.AST = func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
                parts.reverse()
                root = self.mod.imports.get(parts[0])
                if root:
                    # RESOLVED only one attribute deep. `flask.redirect` is the imported
                    # thing itself; `flask.request.args.get` is two attribute accesses
                    # past it, on values whose types this frontend does not have and
                    # cannot get. Calling that resolved is claiming to know that `.get`
                    # here is the dict method, and the whole reason confidence exists is
                    # to avoid claims like that (ADR-005).
                    #
                    # Measured: treating it as resolved put ten findings from four clean
                    # Flask applications into the gating tier, and almost every one was a
                    # redirect the application validates -- through its own helper, or
                    # behind an `is_safe_url` check the engine can see and cannot
                    # evaluate.
                    return {
                        "kind": "external",
                        "symbol": ".".join([root, *parts[1:]]),
                        "resolution": "resolved" if len(parts) <= 2 else "probable",
                    }
                # PROBABLE, not resolved: what `db.engine` IS cannot be established
                # without types, and this frontend has none. The name is evidence and
                # not proof, which is what costs confidence rather than pretending
                # (ADR-005).
                return {
                    "kind": "external",
                    "symbol": ".".join(parts),
                    "resolution": "probable",
                }

        return {"kind": "unresolved", "resolution": "dynamic-unresolved"}


def lower_program(root: str, files: list[str]) -> dict:
    trees: list[tuple[str, ast.Module]] = []
    defs: dict[str, str] = {}

    # Pass 1: module-level function declarations, so calls resolve across files.
    # Registrations are program-wide: `api.add_org_resource(AlertResource, "/api/alerts")`
    # sits in one file and the class it names is defined in another. Collected here, in
    # the pass that already reads every file, so a module can learn that a class of its
    # own is a view without the registering module telling it directly.
    #
    # By NAME, which is loose and is stated: two classes sharing one name would both take
    # the path. A route attributed to the wrong file is still a route, and the alternative
    # was 27 of redash's ~150 routes.
    resource_paths: dict[str, str] = {}
    # Django registers a class-based view by CLASS and dispatches into it by METHOD, so
    # the registration names one thing and the entry points behind it are another.
    class_members: dict[str, dict[str, str]] = {}
    # What each class declares it is, and what every class name in the program holds. A
    # registered Tornado handler is free to define no verb at all and answer entirely in
    # its base, so a registration that stops at the class it names reaches nothing.
    class_bases: dict[str, list[str]] = {}
    members_by_name: dict[str, dict[str, str]] = {}

    for path in files:
        with open(path, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        trees.append((path, tree))
        mid = module_id(root, path)
        dotted = dotted_module(mid)
        for node in tree.body:
            if isinstance(node, FUNCTION_NODES):
                fid = f"{mid}#{node.name}:{node.lineno}:{node.col_offset + 1}"
                defs[f"{mid}:{node.name}"] = fid
                defs[f"import:{dotted}.{node.name}"] = fid
            # Methods, keyed by their class. Registering only module-level functions
            # left `self.helper()` unresolvable, and in a framework whose views are
            # classes that is most of the call graph: 3-5% of calls resolved against
            # 20% for the TypeScript frontend. Every unresolved edge costs twice --
            # taint stops there, and a finding cannot be traced back to the entry point
            # that reaches it.
            elif isinstance(node, ast.ClassDef):
                members: dict[str, str] = {}
                for member in node.body:
                    if isinstance(member, FUNCTION_NODES):
                        fid = f"{mid}#{member.name}:{member.lineno}:{member.col_offset + 1}"
                        defs[f"{mid}:{node.name}.{member.name}"] = fid
                        # And by the name an importer would use, so `Student.create(...)`
                        # in another file resolves to the method rather than stopping at
                        # the class.
                        defs[f"import:{dotted}.{node.name}.{member.name}"] = fid
                        members[member.name] = fid
                # Keyed by the class rather than by the method, because that is what a
                # URLconf names: `path("x/", Detail.as_view())` says nothing about which
                # verbs exist, and the class is the only place that does.
                if members:
                    class_members[f"{mid}:{node.name}"] = members
                    class_members[f"import:{dotted}.{node.name}"] = members
                    members_by_name.setdefault(node.name, members)
                # `class UserAPIHandler(APIHandler)` -- the base as it is WRITTEN, whether
                # that is a bare name or `web.RequestHandler`. Recorded for every class
                # and not only the ones with methods, because a class that adds nothing to
                # its base is exactly the case this exists for.
                bases = [base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
                         for base in node.bases]
                class_bases[f"{mid}:{node.name}"] = bases
                class_bases[f"import:{dotted}.{node.name}"] = bases

    # Registrations are program-wide: `api.add_org_resource(AlertResource, "/api/alerts")`
    # sits in one file and the class it names is defined in another. Collected in a pass
    # of its own so a module can learn that a class of its own is a view without the
    # registering module telling it directly.
    #
    # By NAME, which is loose and is stated: two classes sharing one name would both take
    # the path. A route attributed to the wrong file is still a route, and the alternative
    # was 27 of one application's roughly 150 routes.
    for _, tree in trees:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            attr = node.func.attr
            if attr.startswith("add_") and "resource" in attr and len(node.args) >= 2:
                # add_resource(SomeResource, "/path")
                target, path_arg = node.args[0], node.args[1]
            elif attr == "add_url_rule" and len(node.args) >= 3:
                # Flask's own signature puts the path first and the class third, and the
                # class is routinely imported.
                target, path_arg = node.args[2], node.args[0]
            else:
                continue
            if isinstance(target, ast.Name) and isinstance(path_arg, ast.Constant):
                if isinstance(path_arg.value, str):
                    resource_paths.setdefault(target.id, path_arg.value)

    # Django gives a whole URLconf its prefix from a file that URLconf never mentions:
    # `path("api/v3/", include("hc.api.urls"))` is the only place the routes in that module
    # learn where they are mounted. Program-wide for the same reason resource paths are --
    # the registration and the routes it renames are never in the same file.
    #
    # One level of it. A module mounted under a module that is itself mounted somewhere
    # keeps only the nearer prefix, because composing the two means resolving a chain
    # across files and applications do not write that chain (ADR-003: state the limit
    # rather than let it show up as a route that is missing).
    django_prefixes: dict[str, str] = {}
    for path, tree in trees:
        # A test URLconf mounts the real one wherever the test wants it, and where a test
        # wants it is not where the application serves it.
        if is_test_module(module_id(root, path)):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in DJANGO_REGISTRARS or len(node.args) < 2:
                continue
            included = django_included(node.args[1])
            route = django_route_text(node.args[0])
            if route is None or not isinstance(included, ast.Constant):
                continue
            if isinstance(included.value, str):
                django_prefixes.setdefault(included.value, route)

    # What each class inherits, one level up. Resolved after every file has been read
    # because a base is routinely defined in a module that comes later in the walk, and by
    # NAME for the reason the registration lookups above are -- resolving `APIHandler` to
    # the module it was imported from means reading the import table of the file that
    # declared the subclass, and that file is not the one asking. Bases are merged in
    # reverse so the leftmost wins, which is the order Python resolves them in.
    #
    # ONE level. A base's own base is not followed, because each level costs a name
    # collision's worth of precision and the second level is not where applications put
    # their verbs (ADR-003: state the limit rather than let it show up as a missing route).
    base_members: dict[str, dict[str, str]] = {}
    for key, bases in class_bases.items():
        inherited: dict[str, str] = {}
        for base in reversed(bases):
            inherited.update(members_by_name.get(base, {}))
        if inherited:
            base_members[key] = inherited

    templates = index_templates(root)

    lowerers = [ModuleLowerer(root, path, tree, defs, templates, resource_paths,
                              django_prefixes, class_members, base_members)
                for path, tree in trees]

    # Django's URLconfs, resolved across the program before any module is lowered. A
    # URLconf registers classes that live in other files, and Django's own `View` is one of
    # the bases whose subclasses this frontend already enumerates by verb -- so a module
    # that does not know its class was registered enumerates it a SECOND time, with the
    # class name standing in for the path the registration plainly carries.
    django = {lw.module: [] if is_test_module(lw.module) else lw.django_entry_points()
              for lw in lowerers}
    registered = {entry["functionId"] for entries in django.values() for entry in entries}

    modules, functions, entry_points = [], [], []
    for lowerer in lowerers:
        lowerer.lower(django[lowerer.module], registered)
        modules.append({"id": lowerer.module, "path": lowerer.module,
                        **({"isTest": True} if is_test_module(lowerer.module) else {})})
        functions.extend(lowerer.functions)
        entry_points.extend(lowerer.entry_points)

    return {
        "irVersion": IR_VERSION,
        "frontend": {
            "name": "python",
            "version": FRONTEND_VERSION,
            "capabilities": {
                # Honest: no type inference. Call resolution is name- and
                # import-based, which is enough for interprocedural dataflow but
                # is not a type checker (ADR-003).
                "typeChecker": False,
                "interprocedural": True,
                "crossModule": True,
                "controlFlow": True,
                "templates": bool(templates),
                # Named for what the matcher actually recognizes. The decorator shape
                # also matches FastAPI and Flask-AppBuilder; claiming only "flask"
                # overstated one and understated the others.
                "frameworkModels": ["flask", "flask-appbuilder", "fastapi", "django",
                                    "tornado"],
            },
        },
        "modules": modules,
        "functions": functions,
        "entryPoints": entry_points,
    }
