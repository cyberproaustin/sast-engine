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
import fnmatch
import json
import os
import re
from typing import Any

from declarative import declared_views
from graphene_schema import caller_supplied_params, graphene_entry_points
from registries import (ATTR_VIEW, ConfigClass, ConfigRegistry, ModelViewRegistry,
                        class_name_of)
from templates import index_templates, resolve_template

IR_VERSION = "0.19.0"
FRONTEND_VERSION = "0.1.0"

FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)

# `try` in both its spellings. `except*` is a separate node type with the same four
# fields, and a frontend that knew only about `ast.Try` would lower every 3.11 handler
# as straight-line code again without saying so.
TRY_NODES = tuple(node for node in (ast.Try, getattr(ast, "TryStar", None)) if node is not None)

# Statements whose control flow the block builder does not express. A `match`'s arms all
# appear to run. Inside one of these,
# `self.current` names a block that would claim an edge is unavoidable when it is not --
# so a flow lowered here states no block at all, and the core keeps it. The bias goes one
# way on purpose: a flow with no position is kept, a flow with a wrong position could be
# dropped, and a dropped flow is a missed weakness.
#
# `try` was on this list until its blocks existed. It is off it now: the graph states
# where a handler runs, and a definition in a `try` body is positioned like any other.
# The narrowing was measured rather than assumed -- see the block-building code below.
UNMODELLED_STATEMENTS = tuple(
    node
    for node in (
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

# The same two spellings read for what they DECLARE rather than rewritten. A normalised
# path cannot say which converter a capture was written with, and the converter is the
# only thing that says what the view can be called with: `<uuid:code>` resolves for a
# UUID and for nothing else.
DJANGO_CONVERTER_PARTS = re.compile(r"<(?:([^<>:]+):)?([^<>:]+)>")
DJANGO_NAMED_GROUP = re.compile(r"\(\?P<([^>]+)>")

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


def drf_action(member: ast.AST) -> tuple[list[str], bool, str] | None:
    """`@action(methods=["get"], detail=False)` -- the seventh route of a viewset.

    A router builds the six routes above and one more for EVERY method carrying this
    decorator, off the same class and in the same `register` call. Only the six were
    read, and the cost is not a missing path: it is a missing ENTRY POINT, which is what
    anchors a flow to something a stranger can reach. linkding's `/api/bookmarks/check/`
    takes a URL out of `request.GET` and fetches it, and the engine's own surface report
    named `check` under "nothing in the program calls them by name" while the flow
    sitting behind it was intact and unanchored.

    The path is DRF's own: `url_path` when the decorator writes one, otherwise the method
    name with underscores turned into dashes, under `/<pk>/` when the action is about a
    single record. Defaults are the framework's -- GET, and a list action -- because a
    decorator that omits them still registers a route.
    """
    for decorator in getattr(member, "decorator_list", []):
        if not isinstance(decorator, ast.Call):
            continue
        name = (decorator.func.id if isinstance(decorator.func, ast.Name)
                else getattr(decorator.func, "attr", ""))
        if name != "action":
            continue
        methods, detail = ["GET"], False
        url_path = member.name.replace("_", "-")
        for keyword in decorator.keywords:
            value = keyword.value
            if keyword.arg == "methods" and isinstance(value, (ast.List, ast.Tuple)):
                written = [element.value.upper() for element in value.elts
                           if isinstance(element, ast.Constant)
                           and isinstance(element.value, str)]
                methods = written or methods
            elif keyword.arg == "detail" and isinstance(value, ast.Constant):
                detail = bool(value.value)
            elif (keyword.arg == "url_path" and isinstance(value, ast.Constant)
                  and isinstance(value.value, str)):
                url_path = value.value
        return methods, detail, url_path
    return None


def csrf_exemption(decorators: list[ast.expr]) -> ast.expr | None:
    """The decorator that explicitly removes Django's CSRF enforcement.

    Kept as a declaration fact rather than lowered as middleware: `csrf_exempt` is the
    opposite of the csrf control, and putting both in the same middleware list would make
    the population analysis read an exemption as protection. The core decides what that
    declaration means only when it meets a persistent state change.
    """
    for decorator in decorators:
        if isinstance(decorator, ast.Name) and decorator.id == "csrf_exempt":
            return decorator
        if not isinstance(decorator, ast.Call):
            continue
        name = (decorator.func.id if isinstance(decorator.func, ast.Name)
                else getattr(decorator.func, "attr", ""))
        if name == "csrf_exempt":
            return decorator
        if name != "method_decorator" or not decorator.args:
            continue
        wrapped = decorator.args[0]
        wrapped_name = (wrapped.id if isinstance(wrapped, ast.Name)
                        else getattr(wrapped, "attr", ""))
        if wrapped_name == "csrf_exempt":
            return decorator
    return None


def django_method_restriction(decorators: list[ast.expr]) -> ast.expr | None:
    """A declaration that prevents Django from dispatching every HTTP method.

    The URLconf itself registers a plain function as ANY. These decorators are the
    function's missing half of that contract; treating an `@api_view(["POST"])` as though
    GET reached it manufactured exactly the CSRF shape the decorator rules out.
    """
    fixed = {"require_GET", "require_POST", "require_safe"}
    for decorator in decorators:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = (target.id if isinstance(target, ast.Name)
                else getattr(target, "attr", ""))
        if name in fixed or name in {"api_view", "require_http_methods"}:
            return decorator
    return None


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


# Django's own management-command bases. A class deriving from one of these is a
# command the operator runs from a shell, and its `handle` is where control enters --
# with the application's full privileges, over arguments a person typed.
#
# The base is what decides it, not the directory. `management/commands/` is Django's
# loading convention and it is real corroboration, but a command's identity is its base
# class, and keying on the path would enumerate an `__init__.py` and miss a command a
# project keeps somewhere else.
DJANGO_COMMAND_BASES = frozenset({
    "BaseCommand", "AppCommand", "LabelCommand", "NoArgsCommand", "RunserverCommand",
})

# What the language itself designates as the start of a program.
#
# Module-level code runs at import in EVERY module, so "module-level initialization" on
# its own would make an entry point of every settings file and every constant table in
# the tree -- thousands of them, and the surface is the primary output (ADR-009). What
# narrows it to something true is the language's own rule for which module a process
# starts in: the `__main__` guard, and the file Python runs when handed a package.
MAIN_MODULE = re.compile(r"(^|/)__main__\.py$")


def has_main_guard(tree: ast.Module) -> bool:
    """`if __name__ == "__main__":` at the top level of this module."""
    for node in tree.body:
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if not isinstance(test, ast.Compare) or len(test.comparators) != 1:
            continue
        left, right = test.left, test.comparators[0]
        named = isinstance(left, ast.Name) and left.id == "__name__"
        literal = isinstance(right, ast.Constant) and right.value == "__main__"
        if named and literal:
            return True
    return False




def is_test_module(module: str) -> bool:
    """Ships with the code but does not run in production."""
    return bool(TEST_PATH.search(module))


EXAMPLE_PATH = re.compile(r"(^|/)(examples?|demos?|samples?|docs)(/|$)")
VENDOR_PATH = re.compile(r"(^|/)(vendor|third_party|third-party)(/|$)")

# Directories that hold build and development machinery, and the packaging script the
# language itself names.
#
# Matched only at the TOP LEVEL of the repository. That anchoring is the whole of what
# makes the list safe: an application is free to serve a route from a path with `scripts`
# somewhere in it, and a rule that matched at any depth would delete a live endpoint from
# the surface in order to remove a release script.
TOOLING_DIRS = frozenset({
    "scripts", "devscripts", "dev-scripts", "tools", "tooling", "bundle",
})
TOOLING_FILES = frozenset({"setup.py"})


def is_tooling_module(module: str) -> bool:
    """Build or development machinery rather than the deployed application."""
    parts = module.split("/")
    return (len(parts) > 1 and parts[0] in TOOLING_DIRS) or module in TOOLING_FILES
GENERATED_HEADER = re.compile(
    r"^\s*(?://+|\#|/\*+|\*)\s*(?:(?:this file|code)\s+(?:is\s+)?generated\b|"
    r"generated by\b|auto[- ]generated\b|@generated\b|.*generated[^\n]{0,80}do not edit)",
    re.IGNORECASE | re.MULTILINE)
ORIGINAL_SOURCE = re.compile(
    r"\boriginal source\s*:\s*https?://(?:www\.)?(?:github\.com|gitlab\.com|npmjs\.com)/",
    re.IGNORECASE)
LICENCE_FILES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING")


def module_provenance(root: str, trees: list[tuple[str, ast.Module]]) -> dict[str, str]:
    """Classify source origin without removing any file from the lowered program."""
    workspaces = workspace_patterns(root)
    package_roots: set[str] = set()
    upstream_roots: set[str] = set()

    root_package = read_json(os.path.join(root, "package.json"))
    dependencies = set()
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        value = root_package.get(field, {})
        if isinstance(value, dict):
            dependencies.update(value)

    root = os.path.abspath(root)
    source_text: dict[str, str] = {}
    for source, _tree in trees:
        with open(source, "r", encoding="utf-8") as handle:
            source_text[source] = handle.read()

        directory = os.path.dirname(os.path.abspath(source))
        while directory != root and os.path.commonpath((root, directory)) == root:
            relative = module_id(root, directory)
            nested_package = read_json(os.path.join(directory, "package.json"))
            if (isinstance(nested_package.get("name"), str) and
                    isinstance(nested_package.get("version"), str) and
                    nested_package.get("private") is not True and
                    not matches_workspace(relative, workspaces)):
                package_roots.add(relative)
            if ("modules" in relative.split("/") and
                    any(os.path.isfile(os.path.join(directory, name)) for name in LICENCE_FILES)
                    and not matches_workspace(relative, workspaces)):
                upstream_roots.add(relative)
            directory = os.path.dirname(directory)

        if ("modules" in module_id(root, source).split("/") and
                ORIGINAL_SOURCE.search(source_text[source])):
            upstream_roots.add(module_id(root, os.path.dirname(source)))

        parts = module_id(root, source).split("/")
        if "modules" in parts:
            at = len(parts) - 1 - parts[::-1].index("modules")
            if at + 1 < len(parts) and parts[at + 1] in dependencies:
                upstream_roots.add("/".join(parts[:at + 2]))

    out: dict[str, str] = {}
    for source, tree in trees:
        module = module_id(root, source)
        if EXAMPLE_PATH.search(module):
            out[module] = "example"
        elif is_tooling_module(module):
            out[module] = "tooling"
        elif (VENDOR_PATH.search(module) or
              any(within(module, directory) for directory in package_roots) or
              any(within(module, directory) for directory in upstream_roots)):
            out[module] = "vendored"
        elif (GENERATED_HEADER.search(source_text[source][:4096]) or
              is_generated_data_table(tree)):
            out[module] = "generated"
    return out


def read_json(path: str) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def workspace_patterns(root: str) -> list[str]:
    package = read_json(os.path.join(root, "package.json"))
    declared = package.get("workspaces", [])
    if isinstance(declared, dict):
        declared = declared.get("packages", [])
    patterns = [item for item in declared if isinstance(item, str)] if isinstance(declared, list) else []

    lerna = read_json(os.path.join(root, "lerna.json")).get("packages", [])
    if isinstance(lerna, list):
        patterns.extend(item for item in lerna if isinstance(item, str))
    try:
        with open(os.path.join(root, "pnpm-workspace.yaml"), "r", encoding="utf-8") as handle:
            for line in handle:
                match = re.match(r"\s*-\s*['\"]?([^'\"#]+?)['\"]?\s*$", line)
                if match:
                    patterns.append(match.group(1).strip())
    except OSError:
        pass
    return patterns


def matches_workspace(relative: str, patterns: list[str]) -> bool:
    matched = False
    for raw in patterns:
        negative = raw.startswith("!")
        pattern = raw[1:] if negative else raw
        if fnmatch.fnmatchcase(relative, pattern.removeprefix("./").rstrip("/")):
            matched = not negative
    return matched


def within(module: str, directory: str) -> bool:
    return module == directory or module.startswith(directory + "/")


def is_generated_data_table(tree: ast.Module) -> bool:
    """Recognize a large literal lookup table from structure, not its filename."""
    statements = sum(isinstance(node, ast.stmt) for node in ast.walk(tree))
    assignments = 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        if (value is not None and all(isinstance(target, (ast.Attribute, ast.Subscript))
                                      for target in targets)
                and isinstance(value, ast.Constant)):
            assignments += 1
    return assignments >= 200 and assignments * 10 >= statements * 9


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


def collect_imports(module: str, tree: ast.Module) -> dict[str, str]:
    """Local name -> the dotted origin it was imported from, for one module.

    A module-level function rather than a method, because the program-wide passes need the
    same table before any module is lowered: which base a class actually inherits is a
    question about the IMPORTING file's names, and a pass that runs across files has to
    ask it for a file it is not inside.
    """
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            # A RELATIVE import resolves against this module's own package, and that
            # package is knowable: it is the module's own path with the last segment
            # dropped once per leading dot. Skipping these left `from . import views`
            # binding nothing at all -- which is how Django's own tutorial writes a
            # URLconf, so every route in such a file pointed at a name that resolved
            # to nothing, and every call through one stopped at the import.
            origin = node.module or ""
            if node.level:
                package = dotted_module(module).split(".")[:-node.level]
                origin = ".".join([*package, origin] if origin else package)
            if not origin:
                continue
            for alias in node.names:
                local = alias.asname or alias.name
                imports[local] = f"{origin}.{alias.name}"
    return imports


def decorator_names(node: ast.AST) -> set[str]:
    """The names written in a definition's decorator list, bare or dotted."""
    out: set[str] = set()
    for dec in getattr(node, "decorator_list", []):
        base = dec.func if isinstance(dec, ast.Call) else dec
        name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
        if name:
            out.add(name)
    return out


def implicit_receiver(member: ast.AST) -> str | None:
    """Which receiver Python fills a method's parameter zero from, if any.

    A method declares the receiver as its FIRST parameter and no call site writes it, so
    every argument a caller writes fills the parameter one to its right. Nothing recorded
    that, and the consequence was not a lost finding but a false sentence:
    `cls._set_password_for_user(email, password, token)` against
    `def _set_password_for_user(cls, email, password, token)` bound `password` onto
    `email`, and saleor's setPassword route came out cited as selecting a user record by
    the caller's PASSWORD. The route authenticates by token; the citation was invented by
    the off-by-one.

    Structural, not by the name `self`: the first positional parameter of an instance
    method is the receiver whatever it is called. `@staticmethod` removes the slot
    entirely, and `@classmethod` fills it with the class -- which is bound whether the
    call was written on the class or on an instance, and is why the two answers differ.
    """
    names = decorator_names(member)
    if "staticmethod" in names:
        return None
    args = getattr(member, "args", None)
    if args is None or not (args.posonlyargs or args.args):
        # A method with no positional parameter has no slot for a receiver. Nothing
        # written at the call site can be shifted into one that does not exist.
        return None
    return "class" if "classmethod" in names else "instance"


def django_call_args(node: ast.Call) -> tuple[ast.AST | None, ast.AST | None]:
    """The route and the view of a `path()` call, written either way.

    Django's own tutorial writes `path("x/", views.x)` and its own documentation writes
    `path(route="x/", view=views.x)`, and a great many projects use the second. Reading only
    node.args enumerated 6 entry points of a 78-route application: 51 of doccano's
    registrations name their arguments and 22 do not.

    This is the same mistake as reading an argument's position when it was written as a
    keyword, one level up -- there in a channel, here in a route detector -- and it has now
    cost a surface twice.
    """
    kw = {k.arg: k.value for k in node.keywords if k.arg}
    route = kw.get("route") or kw.get("pattern")
    view = kw.get("view")
    if route is None and node.args:
        route = node.args[0]
    if view is None and len(node.args) > 1:
        view = node.args[1]
    return route, view

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


def route_path_params(route: str) -> str:
    """The captures a route declares, each with the converter it was written with.

    The path `django_route_path` produces has the converter removed -- `<uuid:code>` and
    `<code>` are both `:code` there, because a path is for reading and for matching one
    route against another. What the converter SAYS is a separate fact and not one a
    reader can recover from the normalised path: Django resolves `<uuid:code>` only when
    the segment is a UUID, so the view is never called with anything else in it.

    Recorded as `converter:name`, with an empty converter where the route wrote none.
    Which converters constrain a value enough to matter is a judgement, and it is made in
    the core beside every other judgement about what a value can carry.
    """
    written: list[str] = []
    for match in DJANGO_CONVERTER_PARTS.finditer(route):
        written.append(f"{match.group(1) or ''}:{match.group(2)}")
    for match in DJANGO_NAMED_GROUP.finditer(route):
        written.append(f":{match.group(1)}")
    return ",".join(written)


def django_entry_point(function_id: str, method: str, path: str, route: str = "") -> dict:
    detail = {"method": method, "path": path}
    params = route_path_params(route)
    if params:
        detail["pathParams"] = params
    return {
        "functionId": function_id,
        "kind": "http-route",
        "framework": "django",
        "detail": detail,
    }


def handlers_from_members(members: dict[str, str], path: str, route: str) -> list[dict]:
    """The verbs a class-based view answers, out of the methods it carries.

    One implementation for both registrations that reach a class: the URLconf's
    `X.as_view()` and a config class's `self.<attr>.as_view()`. They name the class two
    different ways and what a class ANSWERS is the same question either way, so writing it
    twice is how the two spellings drift into disagreeing about the same view.
    """
    found = [django_entry_point(members[verb], verb.upper(), path, route)
             for verb in DJANGO_VERB_METHODS if verb in members]
    # FormView implements POST in Django itself and calls the subclass's
    # `form_valid`. The application therefore writes the state-changing handler
    # without writing `post`, and a surface that looks only for verb-named
    # members attributes that route to whichever unrelated hook appears first.
    # archivebox's AddView was consequently represented only by
    # get_context_data while its crawl-creating POST body sat outside the route.
    if "post" not in members and "form_valid" in members:
        found.append(django_entry_point(members["form_valid"], "POST", path, route))
    # Preserve the GET half of a FormView when the subclass customizes its
    # context. Adding the POST must not make an existing entry point disappear.
    if "get" not in members and "get_context_data" in members and "form_valid" in members:
        found.append(django_entry_point(members["get_context_data"], "GET", path, route))
    if found:
        return found
    hook = next((members[name] for name in DJANGO_HOOKS if name in members), None)
    return [django_entry_point(hook, "ANY", path, route)] if hook else []


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
                 base_members: dict[str, dict[str, str]] | None = None,
                 class_actions: dict[str, list[dict]] | None = None,
                 graphql_resolvers: set[int] | None = None,
                 receiver_kinds: dict[str, str] | None = None,
                 class_names: set[str] | None = None,
                 model_views: ModelViewRegistry | None = None,
                 claimed_registrations: set[int] | None = None,
                 strict_bases: dict[str, dict[str, str]] | None = None):
        self.module = module_id(root, path)
        # What a class inherits from a base this program DEFINES, the base resolved
        # through the importing module's names. See `resolved_base_members`: a route may
        # not inherit a method from a class that merely shares a name with its base.
        self.strict_bases = strict_bases or {}
        # The views a decorator bound to a model, so `include(get_model_urls('dcim',
        # 'region'))` can be read as the list of registrations it returns. Program-wide,
        # because the decorator and the URLconf that reads the registry back are never in
        # the same file.
        self.model_views = model_views
        # Registrations a program-wide pass already turned into routes. A registration
        # inside a config class carries a mount prefix only that pass can compose, and
        # emitting it here as well would put the same handler on the surface twice, once
        # at an address the application does not serve.
        self.claimed_registrations = claimed_registrations or set()
        # Which functions in the program take an implicit receiver, and which names are
        # classes. A call resolves to a function id here and the binding of its
        # arguments depends on both -- see FunctionLowerer.receiver_shift.
        self.receiver_kinds = receiver_kinds or {}
        self.class_names = class_names or set()
        # Resolver bodies a GraphQL schema dispatches into, decided program-wide because
        # the registration and the resolver are never in the same file. Their parameters
        # are the arguments a caller named.
        self.graphql_resolvers = graphql_resolvers or set()
        # Every view under the root, read once for the whole program.
        self.templates = templates or {}
        self.tree = tree
        self.global_defs = defs
        self.imports: dict[str, str] = {}
        # Every method of every class in the program, by the name a registration would
        # write for the class. A class-based view is registered by CLASS and answers by
        # METHOD, so the registration names one thing and the entry points are another.
        self.class_members = class_members or {}
        # The extra routes each viewset declares with `@action`, by the same key. A
        # registration names the class; the decorators on its methods are the only place
        # these paths are written down.
        self.class_actions = class_actions or {}
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
        # Where this module hands a context to a view. Collected per module and joined to
        # the views program-wide by the core, because a render and the interpolation it
        # feeds are routinely not in the same file and never in the same language.
        self.renders: list[dict] = []
        # Function nodes whose parameters arrive from an operator rather than from the
        # program: a management command's `handle`, which argparse fills in.
        self.operator_inputs: set[int] = set()
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
        # A dictionary whose values are functions is a finite call graph even when the
        # request chooses its key. searxng's autocomplete dispatch is exactly this
        # shape; dropping the values made an outbound request look like an inert call to
        # a local named `backend`.
        self.callable_collections = self._collect_callable_collections()
        self._collect_route_binders()

    def _collect_imports(self) -> None:
        self.imports.update(collect_imports(self.module, self.tree))

    def _collect_callable_collections(self) -> dict[str, list[str]]:
        """Module dictionaries whose complete value set resolves to local functions."""
        out: dict[str, list[str]] = {}
        for node in self.tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if not isinstance(value, ast.Dict):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [target.id for target in targets if isinstance(target, ast.Name)]
            if not names:
                continue
            candidates: list[str] = []
            complete = True
            for item in value.values:
                target = self._function_reference(item)
                if not target:
                    complete = False
                    break
                candidates.append(target)
            if complete and candidates:
                unique = list(dict.fromkeys(candidates))
                for name in names:
                    out[name] = unique
        return out

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

        # Which `handle` bodies receive operator-supplied arguments. Collected before
        # anything is lowered, because a parameter's KIND is decided as it is created
        # and the walk below creates it.
        command_args = self._command_classes()
        for node in ast.walk(self.tree):
            if isinstance(node, FUNCTION_NODES) and node.name == "handle":
                if self.class_of.get(id(node)) in command_args:
                    self.operator_inputs.add(id(node))

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
                    self.entry_points.extend(
                        self._command_entry_points(node, fn["id"], command_args))

        if not is_test_module(self.module):
            self.entry_points.extend(self._process_start_entry_points())
            self.entry_points.extend(self._url_rule_entry_points())
            self.entry_points.extend(self._router_entry_points())
            self.entry_points.extend(self.tornado_entry_points())
            self.entry_points.extend(django)
        self._collect_resource_paths()

    # --- entry points that are not routes --------------------------------------
    #
    # A route is not the only way into an application. A management command runs with
    # the application's privileges over arguments a person typed, and a process start
    # runs over its configuration and its environment. Neither is reachable by a remote
    # caller, and each says so with its own trust label -- because reporting a command
    # a shell user runs at the same rank as an anonymous request would be a lie in one
    # direction, and burying it would be a lie in the other.

    def _command_classes(self) -> dict[str, list[str]]:
        """Django management-command classes here, each with the arguments it declares.

        The argument names come from `add_arguments`, which is where a command says what
        it accepts. They are evidence on the entry point rather than a source in
        themselves: argparse hands each one to `handle` as a named parameter, and it is
        the parameter that carries the value.
        """
        out: dict[str, list[str]] = {}
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = [base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
                     for base in node.bases]
            if not any(base in DJANGO_COMMAND_BASES for base in bases):
                continue
            out[node.name] = self._declared_arguments(node)
        return out

    @staticmethod
    def _declared_arguments(cls: ast.ClassDef) -> list[str]:
        """`parser.add_argument("--host", ...)` -- every option this command declares."""
        names: list[str] = []
        for member in cls.body:
            if not isinstance(member, FUNCTION_NODES) or member.name != "add_arguments":
                continue
            for node in ast.walk(member):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr != "add_argument" or not node.args:
                    continue
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    names.append(first.value.lstrip("-"))
        return names

    def _command_entry_points(self, node: ast.AST, function_id: str,
                              command_args: dict[str, list[str]]) -> list[dict]:
        """`handle` on a management command: where a shell user's arguments arrive."""
        if getattr(node, "name", "") != "handle":
            return []
        cls = self.class_of.get(id(node))
        if cls not in command_args:
            return []
        # `manage.py <name>` is the module's own basename, which is Django's loading
        # rule and the only name an operator ever types.
        name = self.module.rsplit("/", 1)[-1].removesuffix(".py")
        detail = {"module": self.module, "command": name, "class": cls}
        if command_args[cls]:
            detail["arguments"] = " ".join(command_args[cls])
        return [{
            "functionId": function_id,
            "kind": "cli-command",
            "framework": "django",
            # Someone who can run this already has a shell on the host. That is a lower
            # trust concern than a remote caller and it is emphatically not zero.
            "trust": "operator",
            "detail": detail,
        }]

    def _process_start_entry_points(self) -> list[dict]:
        """The module-level code of a module the LANGUAGE designates as a program start.

        Module-level code runs at import in every module, so the initialization itself is
        not what distinguishes one; what does is that Python starts a process HERE -- at
        a `__main__` guard, or in the `__main__.py` of a package. Everything the start
        reaches is startup code, and startup code reads configuration and the environment
        rather than a request.
        """
        start = ""
        if MAIN_MODULE.search(self.module):
            start = "__main__.py"
        elif has_main_guard(self.tree):
            start = "__main__ guard"
        if not start:
            return []
        return [{
            # The module's own top level, lowered as a function like any other.
            "functionId": f"{self.module}#<module>:0:0",
            "kind": "process-start",
            "trust": "operator",
            "detail": {"module": self.module, "start": start},
        }]

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
            #
            # And it is an EXPRESSION, not a name. `view_func=favicons.favicon_proxy` is
            # how one application registers the only route it declares this way, and a
            # test for `ast.Name` refused it -- so the same helper the other registrars
            # use resolves it here, which is what makes `views.index` work too.
            ref = None
            for kw in node.keywords:
                if kw.arg == "view_func":
                    ref = kw.value
            if ref is None and len(node.args) >= 3:
                ref = node.args[2]
            if ref is None:
                continue

            # A class-based view registered this way gets its path from here; its methods
            # are already entry points by the framework's verb contract. `as_view` is the
            # adapter that makes one -- `Preferences.as_view("preferences")` -- and it has
            # to be named here now that a view_func is read as an expression rather than
            # as a bare name: without it the class is counted a second time, at the same
            # address, with no function behind it.
            if isinstance(ref, ast.Call):
                callee = ref.func
                if isinstance(callee, ast.Attribute) and callee.attr == "as_view":
                    continue
            if isinstance(ref, ast.Name) and ref.id in self.view_classes:
                continue
            # A route whose handler does not resolve STILL EXISTS. `favicon_proxy` is
            # re-exported through a package `__init__`, which this frontend's definition
            # table does not follow, and dropping the route on that account hides an
            # address the application answers at -- the one thing the enumerated surface
            # must never do (ADR-009). The TypeScript side already emits these with no
            # function; this is the same judgement.
            target = self._function_reference(ref)
            paths = self._paths_in(node)
            path = paths[0] if paths else (
                self.path_text(node.args[0]) if node.args else unresolved_path())
            # `add_url_rule(..., methods=["POST"])` is the same declaration the decorator
            # makes, and GET was being applied over the top of it here too.
            for method in self._declared_methods(node):
                out.append({
                    "functionId": target or "",
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
            local = self.global_defs.get(f"{self.module}:{node.id}")
            if local:
                return local
            # A name this module IMPORTED. `from .views import plain_view` and then
            # `path("x/", plain_view)` is how Django's own tutorial registers a function
            # view, and resolving only the current module's globals missed every one of
            # them -- while `SomeClass.as_view()` resolved, because that is an attribute
            # access and took the branch below.
            origin = self.imports.get(node.id)
            if origin:
                return self.global_defs.get(f"import:{origin}.{node.id}") or \
                       self.global_defs.get(f"import:{origin}")
            return None
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
            if node.func.id not in DJANGO_REGISTRARS:
                continue
            if id(node) in self.claimed_registrations:
                continue
            route_node, view = django_call_args(node)
            if route_node is None or view is None:
                continue
            route = django_route_text(route_node)
            if route is None:
                continue
            # An `include(...)` has no handler of its own: the routes it mounts are
            # registered where they are DEFINED, and they pick this prefix up there --
            # unless what it mounts is a REGISTRY read, in which case the registrations
            # are decorators elsewhere and this call is the only place they are addressed.
            included = django_included(view)
            if included is not None:
                for prefix in self._django_prefixes_of(owners.get(id(node)), mounts):
                    out.extend(self._registry_handlers_of(included, prefix + route))
                continue
            for prefix in self._django_prefixes_of(owners.get(id(node)), mounts):
                out.extend(self._django_handlers_of(
                    view, django_route_path(prefix + route), prefix + route))
        return out + self._drf_router_entry_points(mounts)

    def _registry_handlers_of(self, included: ast.AST, mount: str) -> list[dict]:
        """`include(get_model_urls('dcim', 'region'))` -- the routes a registry returns.

        netbox binds a view to a model with a decorator and builds the URLconf by asking
        the registry for that model's views. The two sites name one key and nothing between
        them is a literal, so a reader that matches `path(<literal>, <view>)` sees an
        `include` of a call and stops: 532 declared routes enumerated 128.

        The mount is where THIS call sits and the suffix is what each registration
        declared, which is exactly what the registry's own builder concatenates.
        """
        if self.model_views is None or not isinstance(included, ast.Call):
            return []
        registrations = self.model_views.read(included)
        if not registrations:
            return []
        out: list[dict] = []
        for reg in registrations:
            route = mount + reg.url_path
            members = self._inherited_class_members(f"{reg.module}:{reg.class_name}")
            out.extend(self._handlers_from_members(
                members, django_route_path(route), route))
        return out

    def _django_handlers_of(self, view: ast.AST, path: str, route: str = "") -> list[dict]:
        """The functions one registration reaches, and the verb each of them answers.

        `route` is the registration as it was WRITTEN, carried alongside the normalised
        path because normalising discards the converters, and a converter is what says
        whether a capture can hold anything at all.
        """
        if (isinstance(view, ast.Call) and isinstance(view.func, ast.Attribute)
                and view.func.attr == "as_view"):
            return self._handlers_from_members(
                self._django_class_members(view.func.value), path, route)

        target = self._function_reference(view)
        # ANY, because a URLconf says nothing about the verb: Django calls the function for
        # every one of them and the function decides for itself, usually by reading
        # `request.method`. Naming a verb here would be inventing one.
        return [django_entry_point(target, "ANY", path, route)] if target else []

    def _handlers_from_members(self, members: dict[str, str],
                               path: str, route: str) -> list[dict]:
        """The verbs a class-based view answers, out of the methods it carries."""
        return handlers_from_members(members, path, route)

    def _inherited_class_members(self, key: str) -> dict[str, str]:
        """A class's own methods, and what it inherits where it declares none.

        A netbox view registered by decorator is routinely a class with NO body but a
        queryset: `class RegionListView(generic.ObjectListView)` declares the model and
        the table and inherits `get` from the generic. 1,113 of netbox's 1,141 decorator
        registrations are that shape, so a lookup that stops at the class's own members
        reaches an empty class for all but 28 of them.

        Own members win, which is the order Python resolves them in. The inherited half is
        one level up and RESOLVED -- see `resolved_base_members`: a base that resolves
        outside this program contributes nothing, because a route may not inherit a method
        from a class that merely shares a name with a framework's.
        """
        members = self.class_members.get(key, {})
        inherited = self.strict_bases.get(key, {})
        return {**inherited, **members} if inherited else members

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
        """`router.register("checks", CheckViewSet)` -- six routes, and the extras.

        The prefix has to be a STRING and the class has to be one the program defines with
        something that answers a request: `admin.site.register(Check, CheckAdmin)` and
        `signals.register("check-saved", handler)` are the same word and neither is a
        route, while the registration that IS one always names its path.

        A viewset's `@action` methods are routed by this same call and were not
        enumerated. The router does not distinguish them: `DefaultRouter` walks the class
        once and builds a route for each of the six standard actions AND one for every
        dynamically routed method it finds. Reading six of them and stopping is what left
        linkding's `/api/bookmarks/check/` -- `request.GET["url"]` to `requests.get` --
        outside the surface, with the flow intact and nothing to anchor it to.
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
                                                      django_route_path(base + suffix),
                                                      base + suffix))
                for extra in self._drf_class_actions(node.args[1]):
                    suffix = ("/<pk>/" if extra["detail"] else "/") + extra["urlPath"] + "/"
                    for method in extra["methods"]:
                        out.append(django_entry_point(
                            extra["target"], method, django_route_path(base + suffix),
                            base + suffix))
        return out

    def _drf_class_actions(self, node: ast.AST) -> list[dict]:
        """The `@action` routes of the viewset a registration names, wherever defined."""
        return self.class_actions.get(self._class_key(node) or "", [])

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
            "detail": {
                "method": method,
                "path": path,
                **({"mount": ast.unparse(receiver)} if receiver is not None else {}),
            },
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
        # The statements written at the module's own top level, filled in by `lower`.
        # A class body is reached from there and is not part of it.
        self.module_level: set[int] = set()
        self.enclosing_class = mod.class_of.get(id(node))
        self.values: list[dict] = []
        self.flows: list[dict] = []
        self.calls: list[dict] = []
        self.returns: list[str] = []
        # Index-aligned with `returns`: the block each `return` left the function from.
        # See ir.Function.ReturnBlocks -- without it, "on what condition does this
        # function answer with the value it was handed" has no answer.
        self.return_blocks: list[str] = []
        self.comparisons: list[dict] = []
        self.writes: list[dict] = []
        self.blocks: list[dict] = []
        self._b = 0
        # Depth inside positions reaching-definitions has not been measured over. A
        # match still has no arm graph. Loops now have blocks, but their flows remain
        # deliberately unplaced until narrowing the conservative exclusion is measured
        # as a separate change.
        self.unmodelled = 0
        self.loop_targets: list[tuple[str, str]] = []
        self.comparison_operand = 0
        self.entry_block = self.new_block(node)
        self.current = self.entry_block
        self.params: list[dict] = []
        self.scope: dict[str, str] = {}
        self.prop_cache: dict[str, str] = {}
        self.local_types: dict[str, str] = {}
        self.globals_seen: dict[str, str] = {}
        # Finite indirect targets carried separately from dataflow. A value selected
        # from a literal dispatch table is not one arbitrary dynamic function: its
        # candidates are written down, and retaining that set is what makes reachability
        # through the dispatch auditable.
        self.possible_functions: dict[str, list[str]] = {}
        self.possible_modules: dict[str, list[str]] = {}
        # The names this function was DECLARED with, kept apart from `scope` because a
        # parameter can be reassigned and the question a render asks is about the
        # declaration: "did the caller choose this view name?".
        args = getattr(node, "args", None)
        self.param_names: set[str] = (
            {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)} if args else set()
        )
        self.kwargs_names: set[str] = (
            {args.kwarg.arg} if args is not None and args.kwarg is not None else set()
        )
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

    def path_exists(self, src: str, dst: str) -> bool:
        if src == dst:
            return True
        seen: set[str] = set()
        queue = list((self.block_at(src) or {}).get("successors", []))
        while queue:
            bid = queue.pop(0)
            if bid == dst:
                return True
            if bid in seen:
                continue
            seen.add(bid)
            queue.extend((self.block_at(bid) or {}).get("successors", []))
        return False

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

        Loop bodies retain the conservative reachdef boundary while it is measured
        separately; a `match` arm still has no graph position at all.
        """
        return None if self.unmodelled else self.current

    def lower(self) -> dict:
        # A module's top level is code like any other, and it is where configuration
        # lives: `app.run(debug=True)` is never inside a function. Lowering it as a
        # function of its own lets every analysis kind see it without learning a new
        # shape. The statement walk already stops at function boundaries.
        if self.is_module:
            # A class body is walked as part of the module -- the statement walk stops at
            # functions and not at classes -- so "assigned at module level" has to mean the
            # statement is a direct child of the module and not merely reached from one.
            # `password = graphene.String(description="Password.")` inside a schema class
            # is a field declaration and nothing whatever to do with configuration; it was
            # saleor's one false reading before this distinction existed.
            self.module_level = {id(stmt) for stmt in self.node.body}
            for stmt in self.node.body:
                self.walk(stmt)
            return self._result()

        # A management command's `handle` receives what argparse parsed, so its
        # parameters are values a person typed at a shell. `self` is not one of them.
        operator = id(self.node) in self.mod.operator_inputs

        # A GraphQL resolver is handed the caller's arguments BY NAME. There is no request
        # object to read a property off, so the parameter itself is the origin -- the same
        # judgement, and the same value kind, that an injected NestJS parameter already
        # carries (ADR-004). The framework's own parameters are excluded by name, because
        # `info` is the framework's and `id` is the caller's.
        graphql = (caller_supplied_params(self.node)
                   if id(self.node) in self.mod.graphql_resolvers else set())

        def param_kind(name: str) -> str:
            if name in graphql:
                return "untrusted-param"
            return "operator-param" if operator and name not in ("self", "cls") else "param"

        # Keyword-only parameters participate in name binding even though they have no
        # positional slot in Python source. Keeping them in the declared parameter list
        # is what lets a local `f(value=x)` bind exactly when `value` follows `*`.
        # Positional-only parameters were absent entirely, and a parameter this frontend
        # does not bind is a value that vanishes: `perform_mutation(cls, _root, info, /,
        # *, id)` is how every one of saleor's 315 GraphQL mutations is written, and
        # `info.context.user` inside one lowered to nothing at all because `info` resolved
        # to no value. They come FIRST in the call's positional order, which is what makes
        # the index a rule can name mean what the source says.
        for index, arg in enumerate(
                (*self.node.args.posonlyargs, *self.node.args.args, *self.node.args.kwonlyargs)):
            vid = self.new_value(param_kind(arg.arg), arg, name=arg.arg)
            self.scope[arg.arg] = vid
            self.params.append({"index": index, "name": arg.arg, "valueId": vid})
            # An annotation is the author stating the type outright, which is the
            # strongest thing this frontend will ever have.
            self.note_local_type(arg, arg.annotation, None, name=arg.arg)

        # `**kwargs` is a dict and `*args` is a tuple, always, by the language's own
        # rules — no annotation or inference required.
        #
        # They are PARAMETERS as much as the named ones are, and until they were bound
        # here `options["email"]` inside a management command lowered to nothing at all:
        # the name resolved to no value, so the subscript had no base and the read
        # vanished. A frontend that drops a parameter is not being careful, it is being
        # silent.
        for extra in (self.node.args.vararg, self.node.args.kwarg):
            if extra is None or extra.arg in self.scope:
                continue
            self.local_types[extra.arg] = "tuple" if extra is self.node.args.vararg else "dict"
            vid = self.new_value(param_kind(extra.arg), extra, name=extra.arg)
            self.scope[extra.arg] = vid
            self.params.append({"index": len(self.params), "name": extra.arg, "valueId": vid})

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
            "returnBlocks": self.return_blocks,
            "comparisons": self.comparisons,
            "writes": [{k: v for k, v in w.items() if v is not None} for w in self.writes],
            "entryBlock": self.entry_block,
            "blocks": self.blocks,
        }

    def walk(self, node: ast.AST) -> None:
        # A `match` still chooses between arms the graph does not express. The walk is
        # unchanged; what is suppressed is the CLAIM that a flow inside one sits at a
        # known position. Loops suppress their flows locally for the same conservative
        # reachdef boundary while still emitting their own graph below.
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
                    # A module's own top level is a NAMESPACE, and in Django it is the
                    # configuration namespace: `django.conf.settings.SECRET_KEY` reads the
                    # module-level `SECRET_KEY` of the settings module and there is no
                    # object anywhere in between. Every rule about a configuration write
                    # was therefore blind to the whole framework -- the secret rules match
                    # `app.config["SECRET_KEY"]` and `app.secret_key`, and a bare name has
                    # neither a base nor a property to match, so doccano's committed
                    # fallback key recorded nothing at all.
                    #
                    # Emitted as a write with a SCOPE and no base, because there is no
                    # base: the destination's identity is how far it reaches, which is what
                    # `scope` is for and what the process-wide case above already uses.
                    elif self.is_module and id(node) in self.module_level:
                        self.writes.append({
                            "loc": loc_of(self.mod.module, node),
                            "path": target.id,
                            "from": src,
                            "block": self.write_block(),
                            "scope": "module",
                        })
                    vid = self.new_value("local", target, name=target.id)
                    self.scope[target.id] = vid
                    candidates = self._call_result_candidates(node.value)
                    if candidates:
                        self.possible_functions[target.id] = candidates
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
            before = self.current
            self.unmodelled += 1
            src = self.expr(node.iter)
            self.unmodelled -= 1
            if src is None:
                src = self.new_value("local", node.iter, name=ast.unparse(node.iter))

            # A written, non-empty collection runs the body at least once. This matters
            # independently of its upper bound: rate-limit-scope mounts its control by
            # walking `[limiter_methods]`, and an optional first iteration would turn a
            # control the program certainly installs into one it might skip. The first
            # body is the loop header; the continuation check carries the optional edge
            # after it, which is the same graph a do/while has for the same reason.
            guaranteed_first = (
                isinstance(node.iter, (ast.List, ast.Tuple, ast.Set))
                and any(not isinstance(element, ast.Starred) for element in node.iter.elts)
            )
            body = self.new_block(node)
            after = self.new_block(node)
            else_block = self.new_block(node) if node.orelse else after
            if guaranteed_first:
                header = body
                continuation = self.new_block(node)
                self.link(before, body)
                self.terminate(continuation, "branch")
                self.link(continuation, body)
                self.link(continuation, else_block)
            else:
                header = self.new_block(node)
                continuation = header
                self.link(before, header)
                self.terminate(header, "branch")
                self.link(header, body)
                self.link(header, else_block)
            header_block = self.block_at(header)
            if header_block is not None:
                header_block["loopHeader"] = True
                header_block["loopBound"] = src
            self.current = body
            self.loop_targets.append((continuation, after))
            self.unmodelled += 1
            modules: list[str] = []
            if isinstance(node.iter, (ast.List, ast.Tuple, ast.Set)):
                for item in node.iter.elts:
                    if isinstance(item, ast.Name) and item.id in self.mod.imports:
                        modules.append(self.mod.imports[item.id])
            # Destructuring nests: `for [name, [path, mode]] in request.json` binds three
            # names, and reading only the immediate children found one of them.
            for target in _bound_names(node.target):
                vid = self.new_value("local", target, name=target.id)
                self.scope[target.id] = vid
                if modules:
                    self.possible_modules[target.id] = list(dict.fromkeys(modules))
                if self.is_module:
                    self.mod.module_scope[target.id] = vid
                self.add_flow(src, vid, "property", node)
            for stmt in node.body:
                self.walk(stmt)
            self.unmodelled -= 1
            self.loop_targets.pop()
            if self.path_exists(body, self.current):
                self.link(self.current, continuation)

            if node.orelse:
                self.current = else_block
                self.unmodelled += 1
                for stmt in node.orelse:
                    self.walk(stmt)
                self.unmodelled -= 1
                self.link(self.current, after)
            self.current = after
            return

        if isinstance(node, ast.While):
            header = self.new_block(node)
            self.link(self.current, header)
            self.current = header
            self.unmodelled += 1
            bound = self.expr(node.test)
            self.unmodelled -= 1
            if bound is None:
                bound = self.new_value("local", node.test, name=ast.unparse(node.test))
            header_block = self.block_at(header)
            if header_block is not None:
                header_block["loopHeader"] = True
                header_block["loopBound"] = bound
            self.terminate(header, "branch")

            body = self.new_block(node)
            after = self.new_block(node)
            else_block = self.new_block(node) if node.orelse else after
            self.link(header, body)
            self.link(header, else_block)
            self.current = body
            self.loop_targets.append((header, after))
            self.unmodelled += 1
            for stmt in node.body:
                self.walk(stmt)
            self.unmodelled -= 1
            self.loop_targets.pop()
            if self.path_exists(body, self.current):
                self.link(self.current, header)

            if node.orelse:
                self.current = else_block
                self.unmodelled += 1
                for stmt in node.orelse:
                    self.walk(stmt)
                self.unmodelled -= 1
                self.link(self.current, after)
            self.current = after
            return

        if isinstance(node, ast.Break) and self.loop_targets:
            self.link(self.current, self.loop_targets[-1][1])
            self.current = self.new_block(node)
            return

        if isinstance(node, ast.Continue) and self.loop_targets:
            self.link(self.current, self.loop_targets[-1][0])
            self.current = self.new_block(node)
            return

        if isinstance(node, (ast.Global, ast.Nonlocal)):
            self.declared_global.update(node.names)
            return

        if isinstance(node, ast.AnnAssign):
            src = self.expr(node.value) if node.value else None
            if isinstance(node.target, ast.Name):
                vid = self.new_value("local", node.target, name=node.target.id)
                self.scope[node.target.id] = vid
                # An annotated assignment binds a module name on exactly the same
                # terms as an unannotated one. Keeping it only in this function's scope
                # made every method in the module resolve `name in container` on the
                # left and lose the annotated module global on the right -- SearXNG's
                # digest blacklist was the measured case.
                if self.is_module:
                    self.mod.module_scope[node.target.id] = vid
                self.add_flow(src, vid, "assign", node)
                self.note_local_type(node.target, node.annotation, node.value)
            return

        if isinstance(node, ast.Return):
            if node.value is not None:
                vid = self.expr(node.value)
                if vid:
                    self.returns.append(vid)
                    self.return_blocks.append(self.current)
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

        # A list augmented in place keeps its identity. JupyterHub builds the privileged
        # user-creation argv this way; dropping the right-hand side made the username cease
        # to exist at the exact statement that inserted it.
        if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            dst = self.scope.get(node.target.id)
            src = self.expr(node.value)
            if dst and self.local_types.get(node.target.id) == "list":
                self.add_flow(src, dst, "extend", node)
            return

        # Conditions are not statements and are never reached on their own. The test
        # belongs to the block that branches on it.
        if isinstance(node, ast.If):
            comparisons_before = len(self.comparisons)
            condition = self.expr(node.test)
            if condition and len(self.comparisons) == comparisons_before:
                literal = self.new_value("literal", node.test, literal="true")
                self.comparisons.append(
                    {
                        "left": condition,
                        "right": literal,
                        "op": "truthy",
                        "block": self.current,
                        "loc": loc_of(self.mod.module, node.test),
                    }
                )
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

        # A `try` chooses between paths, and the block graph used to say none of it: the
        # body, every handler and the `finally` were lowered straight-line into one
        # block. A handler's calls then looked like the next thing after the body rather
        # than what runs INSTEAD of the rest of it, and no rule that reads the shape of
        # the graph could say anything about the commonest refusal shape Python has --
        # reject inside a `try`, carry on after it. CWE-698 had never once fired on a
        # Python repository, because the rule that would catch it had no graph to read.
        #
        # The exception edge leaves the try REGION and not any statement inside it, which
        # is why the region gets a block of its own with nothing in it. Hanging that edge
        # on the first block of the BODY instead makes a handler the successor of
        # whatever the body ended up doing, and a body that ends in `return` terminates
        # that very block -- so the handler becomes the one thing that unavoidably
        # follows the refusal, and every handler written under a returning body is
        # reported as execution after a response. That is the defect the TypeScript
        # frontend was corrected for; it is not being rebuilt here.
        #
        # `else` runs only where the body raised nothing, so it continues the body's
        # normal exit and is not on the exception edge at all. `finally` is the one part
        # of a `try` that IS unavoidable, and it is linked from every path into it.
        if isinstance(node, TRY_NODES):
            region = self.new_block(node)
            self.link(self.current, region)
            body = self.new_block(node)
            self.link(region, body)
            self.current = body
            for stmt in list(node.body) + list(node.orelse):
                self.walk(stmt)
            body_end = self.current

            handler_ends: list[str] = []
            for handler in node.handlers:
                block = self.new_block(handler)
                # From the START of the region: an exception can be raised anywhere
                # inside the body, and a statement that has already left the function
                # raises nothing at all.
                self.link(region, block)
                self.current = block
                self.walk(handler)
                handler_ends.append(self.current)

            after = self.new_block(node)
            if node.finalbody:
                final = self.new_block(node)
                self.link(body_end, final)
                for end in handler_ends:
                    self.link(end, final)
                self.current = final
                for stmt in node.finalbody:
                    self.walk(stmt)
                self.link(self.current, after)
            else:
                self.link(body_end, after)
                for end in handler_ends:
                    self.link(end, after)
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

        if self.comparison_operand and isinstance(
            node,
            ast.BinOp,
        ) and isinstance(
            node.op,
            (
                ast.Sub,
                ast.Mult,
                ast.Div,
                ast.FloorDiv,
                ast.Pow,
                ast.LShift,
                ast.RShift,
                ast.BitOr,
                ast.BitXor,
                ast.BitAnd,
                ast.MatMult,
            ),
        ):
            vid = self.new_value("local", node, name="arithmetic")
            self.add_flow(self.expr(node.left), vid, "arithmetic", node)
            self.add_flow(self.expr(node.right), vid, "arithmetic", node)
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
            self.comparison_operand += 1
            try:
                left = self.expr(node.left)
            finally:
                self.comparison_operand -= 1
            vid = self.new_value("local", node, name="comparison")
            for op, comparator in zip(node.ops, node.comparators):
                self.comparison_operand += 1
                try:
                    right = self.expr(comparator)
                finally:
                    self.comparison_operand -= 1
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
            record = self.values[-1]
            # The KEY each member was filed under, for the members whose key was written
            # as a string. A template's context is a mapping and a view reads it BY NAME,
            # so a dict recording only what went into it records the half that cannot
            # answer `{{ query }}`. A computed key is left out rather than guessed at.
            entries = []
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
                member = self.expr(value)
                self.add_flow(member, vid, kind, node)
                if member and isinstance(key, ast.Constant) and isinstance(key.value, str):
                    entries.append({"key": key.value, "valueId": member})
            if entries:
                record["entries"] = entries
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
            # `and` promises BOTH sides, `or` promises either. One value with an edge
            # from each operand cannot tell them apart, and an analysis that admits a
            # value because a check in the condition said yes needs to know which.
            vid = self.new_value("local", node, name="both" if isinstance(node.op, ast.And) else "either")
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

        # The base is VISITED whatever it is, and that is the whole of the fix here.
        # Only an `ast.Name` base was visited before, so `helper(request).name` recorded
        # the call NOWHERE -- not an unresolved symbol, not a missing property, an
        # absent node. The call graph had a hole at every point a program reads a field
        # off a call result, which in an ORM-shaped codebase is everywhere.
        #
        # A property built on whatever came back is the same thing the language does:
        # `f(x).y` is `t = f(x); t.y`, and the second form has always lowered to a
        # property on a call result.
        base = self.expr(cur)
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

        Both sources are local and explicit: an annotation the author wrote
        (`form_data: dict[str, Any] = {}`), or syntax that constructs a builtin here
        (`payload = {}`, a comprehension, or `dict()`). Anything reaching the function
        from elsewhere is unknown, and stays unknown — guessing here would be worse than
        the ambiguity it resolves.
        """
        if isinstance(node, ast.Name):
            return self.local_types.get(node.id)
        if isinstance(node, (ast.Dict, ast.DictComp)):
            return "dict"
        if isinstance(node, (ast.List, ast.ListComp)):
            return "list"
        if isinstance(node, (ast.Set, ast.SetComp)):
            return "set"
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in BUILTIN_CONTAINERS
        ):
            return node.func.id
        return None

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

    def function_ref(self, node: ast.AST) -> str | None:
        """The function this expression NAMES, when the program defines one.

        A function handed to something as an argument is called by whatever receives it,
        and no call site here records that. `functools.partial(self.launch_instance_async,
        argv)` is the shape a process start is written in, and without this the call graph
        ended at the line that hands the function over -- so everything the application
        does after startup was code nothing could reach.

        Only an unambiguous reference counts. A name the function has bound locally is a
        variable that happens to share a spelling, and it is passed over rather than
        guessed at.
        """
        if isinstance(node, ast.Name):
            if node.id in self.scope:
                return None
            local = self.mod.global_defs.get(f"{self.mod.module}:{node.id}")
            if local:
                return local
            imported = self.mod.imports.get(node.id)
            return self.mod.global_defs.get(f"import:{imported}") if imported else None
        if isinstance(node, ast.Attribute):
            if (isinstance(node.value, ast.Name) and node.value.id in ("self", "cls")
                    and self.enclosing_class):
                return self.mod.global_defs.get(
                    f"{self.mod.module}:{self.enclosing_class}.{node.attr}")
            parts: list[str] = []
            cur: ast.AST = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name) and cur.id not in self.scope:
                parts.append(cur.id)
                parts.reverse()
                root = self.mod.imports.get(parts[0])
                if root:
                    return self.mod.global_defs.get(f"import:{'.'.join([root, *parts[1:]])}")
        return None

    def names_a_class(self, node: ast.AST) -> bool:
        """Whether this expression names a CLASS rather than an instance of one.

        The distinction decides who fills parameter zero. `Model.method(instance, x)`
        reaches an unbound function and writes the receiver itself; `obj.method(x)` and
        `self.method(x)` reach a bound one and do not. Both are written the same way, and
        only the base tells them apart.

        A local binding is never a class here even when it holds one, because a name this
        function assigned is a variable and `Model = get_model()` is how applications
        write that. Refusing is the safe direction: it costs the explicit-receiver
        reading, which is the rarer of the two.
        """
        if isinstance(node, ast.Name):
            if node.id == "cls":
                # The class object itself, which is what a classmethod's parameter zero
                # holds. Reached through it, an ordinary method is unbound.
                return True
            if node.id == "self" or node.id in self.scope:
                return False
            if f"{self.mod.module}:{node.id}" in self.mod.class_names:
                return True
            imported = self.mod.imports.get(node.id)
            return bool(imported) and imported in self.mod.class_names
        if isinstance(node, ast.Attribute):
            parts: list[str] = []
            cur: ast.AST = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if not isinstance(cur, ast.Name) or cur.id in self.scope:
                return False
            root = self.mod.imports.get(cur.id)
            if not root:
                return False
            parts.reverse()
            return ".".join([root, *parts]) in self.mod.class_names
        return False

    def receiver_shift(self, node: ast.Call, callee: dict) -> int:
        """How far a written argument sits from the parameter it fills.

        One, whenever the callee declares a receiver the call site did not write --
        which is every `self.m(x)`, every `obj.m(x)`, and every call of a classmethod
        however it was reached, because a classmethod is bound to the class either way.
        Zero for a staticmethod, for a plain function, and for the explicit form
        `Model.method(instance, x)`, where the receiver IS the first written argument.
        """
        fid = callee.get("functionId")
        if not fid:
            return 0
        kind = self.mod.receiver_kinds.get(fid)
        if not kind:
            return 0
        if kind == "class":
            return 1
        func = node.func
        if isinstance(func, ast.Attribute) and self.names_a_class(func.value):
            return 0
        return 1

    def call(self, node: ast.Call) -> str:
        # Resolved before the arguments so each one can be recorded with the parameter
        # it actually fills. Nothing is lowered by resolving; it reads names.
        callee = self.resolve_callee(node)
        shift = self.receiver_shift(node, callee)
        args = []
        literals: dict[int, str] = {}
        for index, arg in enumerate(node.args):
            vid = self.expr(arg)
            entry: dict[str, Any] = {"index": index}
            if shift:
                # The written index stays what it is -- a rule naming "argument 1" means
                # the argument somebody wrote, and argLiterals is keyed by it. Only the
                # binding moves.
                entry["paramIndex"] = index + shift
            if vid:
                entry["valueId"] = vid
            fid = self.function_ref(arg)
            if fid:
                entry["functionId"] = fid
            value_type = self.local_type_of(arg)
            if value_type:
                entry["valueType"] = value_type
                if value_type in BUILTIN_CONTAINERS:
                    entry["valueTypeOrigin"] = "builtin"
            if vid or fid:
                args.append(entry)
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
        # What a `**` SPREAD carries: one mapping, whose keys are decided somewhere else.
        spread: list[str] = []
        for offset, kw in enumerate(node.keywords):
            vid = self.expr(kw.value)
            if vid:
                # A keyword has no positional index until a callee declaration gives it
                # one. Recording the first keyword at len(args) made `login_error=` bind
                # to `self` in a method call with no positional arguments, and every
                # later keyword claimed the same false position. Keep the name: the core
                # can bind it exactly for a local callee and refuses a positional claim
                # for an unresolved one.
                entry: dict[str, Any] = {"valueId": vid}
                if kw.arg:
                    entry["name"] = kw.arg
                fid = self.function_ref(kw.value)
                if fid:
                    entry["functionId"] = fid
                args.append(entry)
                if kw.arg:
                    by_keyword[kw.arg] = vid
                else:
                    spread.append(vid)
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

        # append/extend mutate the list object rather than returning its new contents. The
        # result-value flow therefore cannot carry an inserted caller value to a later
        # Popen; the receiver itself is the value that gained an element.
        # An argument records a valueId, or a functionId, or a name, and not always all
        # three: `queue.append(handler)` carries a function and no value at all. Reading the
        # key unconditionally crashed the whole lowering of mitmproxy, which is worse than
        # any finding it could have produced -- a repository that does not lower contributes
        # nothing, and the run reads as a repository with nothing to say.
        if (receiver and receiver_type == "list" and method in ("append", "extend")
                and args and args[0].get("valueId")):
            self.add_flow(args[0]["valueId"], receiver, method, node)

        # Thread(target=f, args=(...)) invokes f with the tuple's members. SearxNG hands
        # its completed argv to Popen across exactly this boundary, and representing only
        # the Thread object disconnected the callback from the data it receives.
        if callee.get("symbol") == "threading.Thread":
            target = next((kw.value for kw in node.keywords if kw.arg == "target"), None)
            packed = next((kw.value for kw in node.keywords if kw.arg == "args"), None)
            if target is not None and isinstance(packed, (ast.Tuple, ast.List)):
                probe = ast.Call(func=target, args=[], keywords=[])
                ast.copy_location(probe, target)
                callback = self.resolve_callee(probe)
                if callback.get("kind") == "local":
                    callback_args = []
                    for index, element in enumerate(packed.elts):
                        value_id = self.expr(element)
                        if value_id:
                            callback_args.append({"index": index, "valueId": value_id})
                    self.calls.append({
                        "id": f"{self.id}$c{self._c}",
                        "loc": loc_of(self.mod.module, node),
                        "callee": callback,
                        "args": callback_args,
                        "argCount": len(packed.elts),
                        "block": self.current,
                    })
                    self._c += 1

        # Exactly `render_template`. `render_template_string` takes the template SOURCE
        # rather than a name, and is a different weakness with its own rule (CWE-1336).
        #
        # Keyed on the name as WRITTEN as well as on what the call resolved to. A handler
        # that INHERITS `render_template` calls it as `self.render_template(...)`, and a
        # resolved local callee carries a function id and no symbol at all -- so the
        # better the call graph gets, the more template sinks a symbol-only test drops.
        # Measured: resolving inherited methods took jupyterhub's spawn form off the map
        # and with it the only application finding in the repository.
        if "render_template" in ((callee.get("symbol") or "").rsplit(".", 1)[-1], method):
            self.lower_rendered_template(node, by_keyword, spread)
        return result

    def view_name_param(self, node: ast.expr) -> str | None:
        """The parameter this render takes its view name from, or None.

        Not only a bare name. A helper that puts the theme in front of the view --
        `render_template("{}/{}".format(theme, name), **kwargs)` -- is naming the view its
        caller chose, through a prefix the caller did not write; searxng's every page is
        rendered that way and none of them was reachable while the name had to be a
        literal at the call. What is required is that EXACTLY ONE parameter appears in the
        expression, because two would mean guessing which of them is the view.

        The `**kwargs` parameter is deliberately not a candidate: it is the context, and a
        name read out of it is a key rather than a view.
        """
        names = {n.id for n in ast.walk(node)
                 if isinstance(n, ast.Name) and n.id in self.param_names}
        return names.pop() if len(names) == 1 else None

    def lower_rendered_template(
        self, node: ast.Call, by_keyword: dict[str, str], spread: list[str]
    ) -> None:
        """Where a render call ends and a view begins.

        `render_template("page.html", name=x)` hands a set of named values to a file this
        frontend has already read, and that file decides which of them are escaped.

        The two halves are no longer joined HERE. They used to be, and that made the
        analysis require the view name and the context to be written in the same place --
        which real applications do not do. What is recorded instead is the fact: this call
        renders that view, and it binds these names to these values. The join is the
        core's, because a view's free variables are reached from every render of it
        ANYWHERE, through a parent it extends and a file it includes, and no single call
        site can see that.

        A context SPREAD from a mapping -- `render_template(name, **ns)` -- is recorded as
        the mapping itself rather than dropped. Which names it carries is decided wherever
        the mapping is filled in, and that is routinely another function; the core answers
        it program-wide, and a key nobody wrote as a literal still binds nothing.

        Two things this cannot say, each stated rather than guessed at (ADR-003): a view
        name that is neither a literal here nor a parameter this function was handed, and
        a name two templates could answer to.
        """
        name_arg = node.args[0] if node.args else None
        render: dict[str, Any] = {
            "functionId": self.id,
            "loc": loc_of(self.mod.module, node),
            "block": self.current,
        }
        if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str):
            view = resolve_template(self.mod.templates, name_arg.value)
            if view is None:
                return
            render["view"] = view.module
            render["name"] = name_arg.value
        elif name_arg is not None and (chosen := self.view_name_param(name_arg)):
            # A render whose view is named by WHOEVER CALLED THIS. A framework's base
            # handler is written exactly this way -- one method that takes the view name,
            # adds the application-wide namespace and renders -- and it is the shape that
            # put jupyterhub's every page out of reach. The core resolves the name at each
            # call site; this side states only that the parameter is where it comes from.
            render["fromParam"] = chosen
        else:
            return
        bindings = [{"name": key, "valueId": vid} for key, vid in by_keyword.items()]
        if bindings:
            render["bindings"] = bindings
        # `render_template(name, **ns)` hands on whatever its own caller passed, so the
        # bindings written at THIS function's call sites are bindings for the view. The
        # same `**ns` is also a mapping in its own right, and a helper that takes the
        # caller's keywords and then adds a dozen of its own -- which is what an
        # application-wide render helper IS -- supplies both.
        for kw in node.keywords:
            if kw.arg is None and isinstance(kw.value, ast.Name) and kw.value.id in self.kwargs_names:
                render["forwardsKeywords"] = True
        if spread:
            render["contextValues"] = list(spread)
        self.mod.renders.append(render)

    def resolve_callee(self, node: ast.Call) -> dict:
        func = node.func

        if isinstance(func, ast.Name):
            possible = self.possible_functions.get(func.id)
            if possible:
                return {
                    "kind": "unresolved",
                    "possibleFunctionIds": possible,
                    "resolution": "resolved",
                    "name": func.id,
                }
            local = self.mod.global_defs.get(f"{self.mod.module}:{func.id}")
            if local:
                return {"kind": "local", "functionId": local, "resolution": "resolved", "name": func.id}
            imported = self.mod.imports.get(func.id)
            if imported:
                target = self.mod.global_defs.get(f"import:{imported}")
                if target:
                    return {"kind": "local", "functionId": target, "resolution": "resolved", "name": func.id}
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
            modules = self.possible_modules.get(func.value.id, [])
            possible = [
                target
                for module in modules
                if (target := self.mod.global_defs.get(f"import:{module}.{func.attr}"))
            ]
            if possible:
                return {
                    "kind": "unresolved",
                    "possibleFunctionIds": list(dict.fromkeys(possible)),
                    "resolution": "resolved",
                    "name": func.attr,
                }
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
                # A method the class INHERITED, which in a framework whose handlers are
                # subclasses is where the request handling actually lives. jupyterhub's
                # routes name `UserAPIHandler.get`; the code that reads the body, checks
                # the XSRF cookie and validates the next URL is on `APIHandler` and
                # `BaseHandler` two files away, and `self.get_json_body()` resolved to
                # nothing at all. 32 of the 55 input-reading functions no route reached
                # were inherited handler methods -- not routes anybody failed to find.
                #
                # Resolved by NAME and one level up, exactly as the table it reads was
                # built, and PROBABLE for the same reason the same-class case is: the
                # class could rebind the attribute and the base could be a different
                # class of the same name.
                inherited = self.mod.base_members.get(
                    f"{self.mod.module}:{self.enclosing_class}", {}
                ).get(func.attr)
                if inherited:
                    return {"kind": "local", "functionId": inherited, "resolution": "probable"}

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
                    # A definition this program actually holds, found by the name an
                    # importer would write for it. `from jupyterhub import app` then
                    # `app.JupyterHub.launch_instance()` names a classmethod three
                    # segments deep, and the one-level lookup below could not see it --
                    # so the module's own top level called out of the program and the
                    # call graph stopped at the first line of the process. PROBABLE, on
                    # the same terms as the external case: what sits between the root and
                    # the leaf is a name, not a type this frontend has.
                    dotted = ".".join([root, *parts[1:]])
                    deep = self.mod.global_defs.get(f"import:{dotted}")
                    if deep and len(parts) > 2:
                        return {"kind": "local", "functionId": deep,
                                "resolution": "probable"}
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

    def _call_result_candidates(self, node: ast.AST) -> list[str]:
        """Targets selected from a module-level literal dispatch dictionary."""
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            return []
        if node.func.attr not in ("get", "__getitem__"):
            return []
        receiver = node.func.value
        if not isinstance(receiver, ast.Name):
            return []
        return self.mod.callable_collections.get(receiver.id, [])


# --- What a view class inherits, with the base RESOLVED ----------------------
#
# The program-wide base table beside this merges by BARE NAME, which is enough for the
# question it was built for and is not enough for a route. Measured on django-oscar:
# `class UserAddressUpdateView(CheckoutSessionMixin, generic.UpdateView)` inherits its
# verbs from DJANGO's UpdateView, and matching the bare name found the application's own
# unrelated `UpdateView` in `communication/notifications/views.py` -- whose `delete` is a
# bulk action taking a list of notifications. Eighteen routes were bound to it, each one a
# claim that a DELETE at that address runs that function. It does not.
#
# So the base is resolved through the importing module's own names first. What that buys
# is the ability to tell a framework base from an application one, which is the whole
# judgement: a base that resolves OUTSIDE the program contributes nothing, because the
# program does not contain the method and inventing one is the phantom above.


def module_suffixes(modules: list[str]) -> set[str]:
    """Every dotted name that addresses a module of this program.

    A repository is not a package root. django-oscar's `oscar` package sits under `src/`
    and netbox's `netbox` package sits under `netbox/`, so the dotted name an import
    writes is a SUFFIX of the module id and never equal to it. `__init__` is dropped
    because an importer names the package, not the file inside it.
    """
    out: set[str] = set()
    for module in modules:
        dotted = dotted_module(module)
        if dotted.endswith(".__init__"):
            dotted = dotted[: -len(".__init__")]
        elif dotted == "__init__":
            continue
        parts = dotted.split(".")
        for start in range(len(parts)):
            out.add(".".join(parts[start:]))
    return out


def _base_key(imports: dict[str, str], module: str, base: ast.AST) -> tuple[str, str] | None:
    """One base as (lookup key, origin module), out of how the subclass wrote it."""
    if isinstance(base, ast.Name):
        origin = imports.get(base.id)
        if origin:
            return f"import:{origin}", origin.rsplit(".", 1)[0]
        # Defined in this module, or arrived through a star import. Either way the name is
        # this program's own and the module it names is this one.
        return f"{module}:{base.id}", dotted_module(module)
    if isinstance(base, ast.Attribute):
        parts: list[str] = []
        cur: ast.AST = base
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if not isinstance(cur, ast.Name):
            return None
        root = imports.get(cur.id, cur.id)
        dotted = ".".join([root, *reversed(parts)])
        return f"import:{dotted}", dotted.rsplit(".", 1)[0]
    return None


def resolved_base_members(trees: list[tuple[str, ast.Module]],
                          class_members: dict[str, dict[str, str]],
                          members_by_name: dict[str, dict[str, str]],
                          suffixes: set[str]) -> dict[str, dict[str, str]]:
    """Class key -> the methods it inherits from bases this PROGRAM defines.

    Three answers per base and they are ranked. The exact key wins, because a resolved
    import names one class and no other. A base whose module is this program's but whose
    exact key is not found falls back to the bare name -- that is the package re-export
    case, `from netbox.views import generic` reaching a class defined three files inside
    the package, and 1,113 of netbox's registrations inherit every verb they answer
    through one. A base whose module is NOT this program's answers nothing at all.

    Merged leftmost-wins, which is the order Python resolves a method in.
    """
    out: dict[str, dict[str, str]] = {}
    for module, tree in trees:
        imports = collect_imports(module, tree)
        dotted = dotted_module(module)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            inherited: dict[str, str] = {}
            for base in reversed(node.bases):
                found = _base_key(imports, module, base)
                if found is None:
                    continue
                key, origin = found
                members = class_members.get(key)
                if members is None and origin in suffixes:
                    members = members_by_name.get(class_name_of(base))
                if members:
                    inherited.update(members)
            if inherited:
                out[f"{module}:{node.name}"] = inherited
                out[f"import:{dotted}.{node.name}"] = inherited
    return out


# --- Routes a method returns ------------------------------------------------
#
# django-oscar has no module-level `urlpatterns` anywhere. Every application is a class
# and each contributes its routes by overriding `get_urls()`, so the registration, the
# view it points at, and the prefix it is served under are three facts in three files:
# 219 declared routes enumerated 30, and 828 Python files reached 30 entry points while
# 279 functions reading caller input were reachable from nothing.
#
# Resolved program-wide rather than per module, because none of the three facts is in the
# file that needs it. A registration inside `CatalogueDashboardConfig.get_urls()` points
# at `self.product_list_view`, which `ready()` loaded by name from another package, and is
# served under `dashboard/catalogue/` because a THIRD config mounted this one by label.

# How many mount paths one config class may be resolved to. The bound the module-level
# URLconf walk uses, for the same reason: an application that cross-mounts its configs
# would otherwise turn one registration into thousands of paths.
MAX_CONFIG_MOUNTS = 16


def django_view_expr(node: ast.AST) -> ast.AST:
    """A view with its access decorators peeled off.

    `login_required(self.summary_view.as_view())` is a view and a gate written as one
    expression, and 33 of oscar's 196 registrations are written that way. What is being
    registered is the view: the wrapper delegates to it, so the handler the route reaches
    is inside. Peeled by looking for the argument that is itself a view expression rather
    than by naming the decorators, because an application writes its own.
    """
    for _ in range(4):
        if not isinstance(node, ast.Call) or isinstance(node.func, ast.Attribute):
            return node
        inner = [a for a in node.args
                 if isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute)
                 and a.func.attr == "as_view"]
        if len(inner) != 1:
            return node
        node = inner[0]
    return node


def config_route_entry_points(
        configs: ConfigRegistry,
        class_members: dict[str, dict[str, str]],
        base_members: dict[str, dict[str, str]]) -> tuple[dict[str, list[dict]], set[int]]:
    """The routes config classes declare, and the registration nodes this claimed.

    The claimed set is returned so the per-module URLconf walk can leave these
    registrations alone: it would find the same calls, resolve `self.<attr>` to nothing,
    and give the few it does resolve the prefix of a file rather than of a mount.
    """
    mounts = _config_mounts(configs)
    # Bare class name -> the program keys that name it. Built once: a config resolves its
    # view by name and there are tens of thousands of keys in a large program, so asking
    # the question per registration is a scan of the whole table per route.
    by_class_name: dict[str, list[str]] = {}
    for table in (class_members, base_members):
        for key in table:
            if key.startswith("import:"):
                continue
            name = key.rsplit(":", 1)[-1]
            if key not in by_class_name.setdefault(name, []):
                by_class_name[name].append(key)
    out: dict[str, list[dict]] = {}
    claimed: set[int] = set()

    for cls in configs.declaring():
        label = configs.label_of(cls)
        if label is None:
            # Not an app config. A `get_urls()` on a Django ModelAdmin or on a custom DRF
            # router is the same method name and the same shape, and the routes it returns
            # are mounted by machinery that writes no label -- so their address is not
            # readable and a route at an unknown address is a claim about one that is not
            # served (ADR-009).
            continue
        prefixes = _config_prefixes(configs, cls, mounts)
        for call in cls.registrations:
            entries = _config_registration_entries(
                configs, cls, call, prefixes, class_members, base_members, by_class_name)
            if entries is None:
                continue
            claimed.add(id(call))
            out.setdefault(cls.module, []).extend(entries)
    return out, claimed


def _config_mounts(configs: ConfigRegistry) -> dict[str, list[tuple[str, object]]]:
    """App label -> every route it is mounted at, and the config that mounted it.

    `path("dashboard/", self.dashboard_app.urls)` inside one config and
    `path('', include(apps.get_app_config('oscar').urls[0]))` at the top of a root URLconf
    are the same mount at two levels, and the chain between them is what says a dashboard
    route is served at `dashboard/catalogue/products/` rather than at `products/`.

    A mount written outside any config class carries no further prefix: the module-level
    walk that would compose one runs per file and this pass is program-wide. Stated rather
    than guessed -- the root URLconf is where applications write the empty prefix anyway.
    """
    mounts: dict[str, list[tuple[str, object]]] = {}
    for cls in configs.classes:
        for call in cls.registrations:
            route_node, view = django_call_args(call)
            if route_node is None or view is None:
                continue
            route = django_route_text(route_node)
            if route is None:
                continue
            target = django_included(view)
            label = configs.mounted_label(cls, target if target is not None else view)
            if label is not None:
                mounts.setdefault(label, []).append((route, cls))
    for route, label in configs.module_level_mounts:
        mounts.setdefault(label, []).append((route, None))
    return mounts


def _config_prefixes(configs: ConfigRegistry, cls: ConfigClass,
                     mounts: dict[str, list[tuple[str, object]]]) -> list[str]:
    """Every path this config's routes are served under, mounts composed.

    Bounded and cycle-safe for the reason the module-level version is: this is a walk over
    data an application wrote, and an application is free to write a cycle into it.
    """
    label = configs.label_of(cls)
    found: list[str] = []
    pending: list[tuple[str | None, str, frozenset]] = [(label, "", frozenset())]
    while pending and len(found) < MAX_CONFIG_MOUNTS:
        current, suffix, seen = pending.pop()
        if current is None or current not in mounts or current in seen:
            # A config nothing mounts still declares its routes, and an unresolved mount
            # contributes the empty prefix rather than dropping them (ADR-009).
            if suffix not in found:
                found.append(suffix)
            continue
        for route, parent in mounts[current]:
            parent_label = configs.label_of(parent) if parent is not None else None
            pending.append((parent_label, route + suffix, seen | {current}))
    return found


def _config_registration_entries(configs: ConfigRegistry, cls: ConfigClass,
                                 call: ast.Call,
                                 prefixes: list[str],
                                 class_members: dict[str, dict[str, str]],
                                 base_members: dict[str, dict[str, str]],
                                 by_class_name: dict[str, list[str]]) -> list[dict] | None:
    """One registration, at every path the config that declares it is served under.

    None where the registration is not this pass's to make: a mount has no handler of its
    own, and a view spelling this cannot read is left to the per-module walk that may.
    """
    route_node, view = django_call_args(call)
    if route_node is None or view is None:
        return None
    route = django_route_text(route_node)
    if route is None:
        return None
    if django_included(view) is not None or configs.mounted_label(cls, view) is not None:
        # A mount. Its routes are registered where they are DECLARED and pick this prefix
        # up there, which is what `_config_mounts` recorded it for. Left UNCLAIMED rather
        # than claimed-and-empty, so that the per-module walk still gets its own look: it
        # resolves an app-config mount to nothing, and an `include` of a registry read is
        # the one shape it can expand and this pass cannot.
        return None
    members = _config_view_members(
        configs, cls, view, class_members, base_members, by_class_name)
    if members is None:
        return None
    out: list[dict] = []
    for prefix in prefixes:
        full = prefix + route
        out.extend(handlers_from_members(members, django_route_path(full), full))
    return out or None


def _config_view_members(configs: ConfigRegistry, cls: ConfigClass, view: ast.AST,
                         class_members: dict[str, dict[str, str]],
                         base_members: dict[str, dict[str, str]],
                         by_class_name: dict[str, list[str]]) -> dict[str, str] | None:
    """The methods behind `self.<attr>.as_view()`, or None where the view is not one.

    The attribute is resolved on the class and its bases -- oscar's configs assign in
    `ready()`, which is Django's own place for it -- and the class name it holds is
    resolved program-wide, which is the resolution every registration lookup in this
    frontend already uses. A name two modules both define resolves to NOTHING: binding a
    route to whichever the walk reached first is a claim about an address the application
    does not serve.
    """
    view = django_view_expr(view)
    if not (isinstance(view, ast.Call) and isinstance(view.func, ast.Attribute)
            and view.func.attr == "as_view"):
        return None
    holder = view.func.value
    if not (isinstance(holder, ast.Attribute) and isinstance(holder.value, ast.Name)
            and holder.value.id == "self"):
        # `SomeView.as_view()` written out. The per-module walk resolves that spelling
        # against this file's own imports, which is a better answer than a name match.
        return None
    held = configs.attribute(cls, holder.attr)
    if held is None or held[0] != ATTR_VIEW:
        return None
    keys = by_class_name.get(held[1], ())
    if len(keys) != 1:
        return None
    key = keys[0]
    members = class_members.get(key, {})
    inherited = base_members.get(key, {})
    return {**inherited, **members} if inherited else members


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
    # The routes a viewset declares that are NOT one of the standard six, keyed the same
    # way. `@action` is read where every other member is read, because it is the same
    # registration: one `router.register` line builds the six and these together.
    class_actions: dict[str, list[dict]] = {}
    # What each class declares it is, and what every class name in the program holds. A
    # registered Tornado handler is free to define no verb at all and answer entirely in
    # its base, so a registration that stops at the class it names reaches nothing.
    class_bases: dict[str, list[str]] = {}
    members_by_name: dict[str, dict[str, str]] = {}
    # How many classes in the program carry each name. A base matched by NAME is only
    # matched where the name means one thing: binding a route through a name two classes
    # share is how eighteen of oscar's routes were bound to an unrelated bulk action.
    name_counts: dict[str, int] = {}
    # Which methods declare an implicit receiver, and which names in the program are
    # CLASSES. Together they decide whether a written argument fills the parameter it
    # sits above or the one to its right, which is a fact about the callee and the
    # spelling of the receiver rather than about the call's own text -- so it is
    # collected here, in the pass that already reads every definition.
    receiver_kinds: dict[str, str] = {}
    class_names: set[str] = set()
    # Function id -> the source location of a declaration that removes CSRF checking.
    # Collected program-wide because the URLconf and the decorated view normally live in
    # different modules, just like the class member table beside it.
    csrf_exemptions: dict[str, dict[str, object]] = {}
    method_restrictions: set[str] = set()

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
                exemption = csrf_exemption(node.decorator_list)
                if exemption is not None:
                    csrf_exemptions[fid] = {
                        "file": mid, "line": exemption.lineno,
                        "column": exemption.col_offset + 1,
                    }
                if django_method_restriction(node.decorator_list) is not None:
                    method_restrictions.add(fid)
            # Methods, keyed by their class. Registering only module-level functions
            # left `self.helper()` unresolvable, and in a framework whose views are
            # classes that is most of the call graph: 3-5% of calls resolved against
            # 20% for the TypeScript frontend. Every unresolved edge costs twice --
            # taint stops there, and a finding cannot be traced back to the entry point
            # that reaches it.
            elif isinstance(node, ast.ClassDef):
                members: dict[str, str] = {}
                actions: list[dict] = []
                name_counts[node.name] = name_counts.get(node.name, 0) + 1
                # Both spellings a call site can reach this class by, so a receiver
                # written as `Model.method(instance, x)` is recognised as the class it
                # names whichever way the importer spelled it.
                class_names.add(f"{mid}:{node.name}")
                class_names.add(f"{dotted}.{node.name}")
                class_exemption = csrf_exemption(node.decorator_list)
                for member in node.body:
                    if isinstance(member, FUNCTION_NODES):
                        fid = f"{mid}#{member.name}:{member.lineno}:{member.col_offset + 1}"
                        receiver = implicit_receiver(member)
                        if receiver:
                            receiver_kinds[fid] = receiver
                        defs[f"{mid}:{node.name}.{member.name}"] = fid
                        # And by the name an importer would use, so `Student.create(...)`
                        # in another file resolves to the method rather than stopping at
                        # the class.
                        defs[f"import:{dotted}.{node.name}.{member.name}"] = fid
                        members[member.name] = fid
                        member_exemption = csrf_exemption(member.decorator_list)
                        exemption = member_exemption or class_exemption
                        if exemption is not None:
                            csrf_exemptions[fid] = {
                                "file": mid, "line": exemption.lineno,
                                "column": exemption.col_offset + 1,
                            }
                        route = drf_action(member)
                        if route is not None:
                            methods, detail, url_path = route
                            actions.append({"target": fid, "methods": methods,
                                            "detail": detail, "urlPath": url_path})
                # Keyed by the class rather than by the method, because that is what a
                # URLconf names: `path("x/", Detail.as_view())` says nothing about which
                # verbs exist, and the class is the only place that does.
                if members:
                    class_members[f"{mid}:{node.name}"] = members
                    class_members[f"import:{dotted}.{node.name}"] = members
                    members_by_name.setdefault(node.name, members)
                if actions:
                    class_actions[f"{mid}:{node.name}"] = actions
                    class_actions[f"import:{dotted}.{node.name}"] = actions
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

    # The declarative half of the program's views, resolved before any module is lowered
    # for the reason the URLconfs are: a view names a permission class three packages
    # away, and neither file knows the other exists. Test modules are left out, because a
    # test registers whatever view it wants to exercise and none of that is served.
    declared = declared_views(
        [(module_id(root, path), tree) for path, tree in trees
         if not is_test_module(module_id(root, path))],
        lambda module, node: f"{module}#{node.name}:{node.lineno}:{node.col_offset + 1}")

    # The GraphQL schema, resolved before any module is lowered and for the same reason the
    # URLconfs are: `schema.py` names a mutation class it never defines, and the module that
    # defines one never learns it was registered. A test module is left out because a test
    # composes whatever schema it wants to exercise and none of that is served.
    production = [(module_id(root, path), tree) for path, tree in trees
                  if not is_test_module(module_id(root, path))]
    graphql_entries, graphql_resolvers = graphene_entry_points(
        production,
        lambda module, node: f"{module}#{node.name}:{node.lineno}:{node.col_offset + 1}")

    # The two route registries, resolved before any module is lowered and for the reason
    # the URLconfs are: a decorator in `views.py` and the `get_model_urls` call in
    # `urls.py` name one key, and a config class declares routes a DIFFERENT config
    # class mounts. Test modules are left out because a test registers whatever surface
    # it wants to exercise and none of that is served.
    model_views = ModelViewRegistry(production)
    # What a registered view class inherits, with each base resolved through the importing
    # module's own names. Separate from the bare-name table above and not a replacement for
    # it: this one answers "is that base in this program at all", which is what a route may
    # not get wrong, and answering it costs the looseness the other table is built on.
    strict_bases = resolved_base_members(
        [(module_id(root, path), tree) for path, tree in trees], class_members,
        {name: members for name, members in members_by_name.items()
         if name_counts.get(name, 0) == 1},
        module_suffixes([module_id(root, path) for path, _ in trees]))
    config_routes, claimed = config_route_entry_points(
        ConfigRegistry(production), class_members, strict_bases)

    lowerers = [ModuleLowerer(root, path, tree, defs, templates, resource_paths,
                              django_prefixes, class_members, base_members,
                              class_actions, graphql_resolvers, receiver_kinds,
                              class_names, model_views, claimed, strict_bases)
                for path, tree in trees]
    provenance = module_provenance(root, trees)

    # Django's URLconfs, resolved across the program before any module is lowered. A
    # URLconf registers classes that live in other files, and Django's own `View` is one of
    # the bases whose subclasses this frontend already enumerates by verb -- so a module
    # that does not know its class was registered enumerates it a SECOND time, with the
    # class name standing in for the path the registration plainly carries.
    django = {lw.module: [] if is_test_module(lw.module) else lw.django_entry_points()
              for lw in lowerers}
    for module, entries in config_routes.items():
        django.setdefault(module, []).extend(entries)
    registered = {entry["functionId"] for entries in django.values() for entry in entries}

    modules, functions, entry_points, renders = [], [], [], []
    for lowerer in lowerers:
        lowerer.lower(django[lowerer.module], registered)
        modules.append({"id": lowerer.module, "path": lowerer.module,
                        **({"isTest": True} if is_test_module(lowerer.module) else {}),
                        **({"provenance": provenance[lowerer.module]}
                           if lowerer.module in provenance else {})})
        functions.extend(lowerer.functions)
        entry_points.extend(lowerer.entry_points)
        renders.extend(lowerer.renders)
    entry_points.extend(graphql_entries)

    # The declaration belongs to the entry point, not to a call. Detail is intentionally
    # used rather than middleware: the existing csrf control classifier matches names,
    # and an exemption carrying that name must never satisfy the control it removes.
    for entry in entry_points:
        if entry.get("functionId", "") in method_restrictions:
            entry.setdefault("detail", {})["methodRestricted"] = "true"
        exemption = csrf_exemptions.get(entry.get("functionId", ""))
        if exemption is None:
            continue
        detail = entry.setdefault("detail", {})
        detail["csrfExempt"] = "true"
        detail["csrfExemptFile"] = str(exemption["file"])
        detail["csrfExemptLine"] = str(exemption["line"])
        detail["csrfExemptColumn"] = str(exemption["column"])

    # The views, with the graph between them resolved to ids here rather than left as the
    # names they were written with. Which file a name reaches is a question about this
    # tree and about the loader's search path, and the core has neither.
    views = []
    for template in templates.values():
        if not template.reads and not template.extends and not template.includes:
            continue
        view: dict[str, Any] = {"id": template.module}
        parents = [resolve_template(templates, name, template.module) for name in template.extends]
        parents = [p.module for p in parents if p is not None]
        if parents:
            view["extends"] = parents
        includes = []
        for entry in template.includes:
            target = resolve_template(templates, entry["view"], template.module)
            if target is None:
                continue
            includes.append({"view": target.module,
                             **({"rebind": entry["rebind"]} if entry.get("rebind") else {})})
        if includes:
            view["includes"] = includes
        if template.reads:
            view["reads"] = [
                {"path": r["path"], "escaped": r["escaped"],
                 "loc": {"file": template.module, "line": r["line"], "column": r["column"]},
                 **({"context": r["context"]} if r.get("context") else {}),
                 **({"removedAt": r["removedAt"]} if r.get("removedAt") else {})}
                for r in template.reads
            ]
        views.append(view)

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
                # `drf` is named apart from `django` deliberately (ADR-003). A Django
                # URLconf and a Django REST Framework view class are two different
                # idioms: the first registers a function this frontend can lower, the
                # second declares attributes the framework reads and writes no handler at
                # all. Claiming "django" covered both would have reported an analysis of
                # declarative views as clean on a program whose views were never read.
                # `graphene` is named apart from `django` for the reason `drf` is
                # (ADR-003). A GraphQL schema is a third idiom: the URLconf registers one
                # view and the operations behind it are class attributes no route mentions,
                # so a scan of a Django application WITHOUT a schema must report the
                # graphene judgements NOT EVALUATED rather than silently clean.
                "frameworkModels": ["flask", "flask-appbuilder", "fastapi", "django",
                                    "drf", "graphene", "tornado"],
            },
        },
        "modules": modules,
        "functions": functions,
        "entryPoints": entry_points,
        "declaredViews": declared,
        "views": views,
        "renders": renders,
    }
