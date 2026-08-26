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

IR_VERSION = "0.12.0"
FRONTEND_VERSION = "0.1.0"

FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)

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


class ModuleLowerer:
    """Lowers one module. Imports and module-level defs are resolved by name."""

    def __init__(self, root: str, path: str, tree: ast.Module, defs: dict[str, str],
                 templates: dict | None = None, resource_paths: dict[str, str] | None = None):
        self.module = module_id(root, path)
        # Every view under the root, read once for the whole program.
        self.templates = templates or {}
        self.tree = tree
        self.global_defs = defs
        self.imports: dict[str, str] = {}
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
        self._collect_imports()

    def _collect_imports(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    local = alias.asname or alias.name
                    self.imports[local] = f"{node.module}.{alias.name}"

    def lower(self) -> None:
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
                    if single:
                        found = [single]
                # A test file's routes are not the application's attack surface: a test
                # client is CALLED exactly as a router is REGISTERED, and a route that
                # exists only in a test does not exist in the program that is deployed.
                if not is_test_module(self.module):
                    self.entry_points.extend(found)

        if not is_test_module(self.module):
            self.entry_points.extend(self._url_rule_entry_points())
            self.entry_points.extend(self._router_entry_points())
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
            out.append({
                "functionId": target,
                "kind": "http-route",
                "framework": "flask",
                "detail": {"method": "GET", "path": paths[0] if paths else "*"},
            })
        return out

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
                path = self._constant(node.args[1]) or "*"
                handler = node.args[2]
            elif attr in self._VERB_METHODS:
                # add_get(path, handler) and web.get(path, handler). A bare `get` or
                # `post` is only a route when it is given a FUNCTION -- `session.get(key)`
                # and `requests.get(url)` are the same two words and are not routes, which
                # is why the handler has to resolve before anything is recorded.
                if len(node.args) < 2:
                    continue
                method = self._VERB_METHODS[attr]
                path = self._constant(node.args[0]) or "*"
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

    # --- Flask framework model -------------------------------------------
    #
    # Isolated here for the same reason the Express model is isolated in the
    # TypeScript frontend (ADR-004): framework knowledge is data about a
    # framework, not a property of the language.

    def entry_points_for(self, node: ast.AST, function_id: str) -> list[dict]:
        out = []
        for dec in getattr(node, "decorator_list", []):
            entry = self._entry_point_for_decorator(dec, function_id)
            if entry:
                out.append(entry)
        return out

    def _entry_point_for_decorator(self, dec: ast.AST, function_id: str) -> dict | None:
        if True:
            if not isinstance(dec, ast.Call):
                return None

            # `@app.route(...)`, `@router.get(...)` — bound to an object.
            if isinstance(dec.func, ast.Attribute):
                attr = dec.func.attr
                framework = "flask"
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
                    return None
                framework = "flask-appbuilder"
            else:
                return None

            # An error handler is reached by making a request that fails, which is
            # something any caller can do on purpose. It reads the request object like
            # any other handler, and a vulnerable Flask application interpolates
            # `request.url` into a template inside one. Treating it as unreachable left
            # a real template injection in the unanchored section, where nothing gates.
            if attr == "errorhandler":
                return {
                    "functionId": function_id,
                    "kind": "http-route",
                    "framework": framework,
                    "detail": {"method": "ANY", "path": "<error handler>"},
                }

            if attr not in ("route", "expose", "get", "post", "put", "patch", "delete"):
                return None

            path = "*"
            if dec.args and isinstance(dec.args[0], ast.Constant):
                path = str(dec.args[0].value)
            # A verb decorator whose first argument is not a PATH is not a route.
            # `@mock.patch("sqli.dao.user.User")` and `@pytest.mark.parametrize(...)` are
            # written the same way and mean something else entirely.
            if attr not in ("route", "expose") and not path.startswith("/"):
                return None

            methods = ["GET"] if attr in ("route", "expose") else [attr.upper()]
            for kw in dec.keywords:
                if kw.arg == "methods" and isinstance(kw.value, ast.List):
                    found = [
                        str(e.value) for e in kw.value.elts if isinstance(e, ast.Constant)
                    ]
                    if found:
                        methods = found

            return {
                "functionId": function_id,
                "kind": "http-route",
                "framework": framework,
                "detail": {"method": methods[0], "path": path},
            }
        return None


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
            self.flows.append(
                {"from": src, "to": dst, "kind": kind, "loc": loc_of(self.mod.module, node)}
            )

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
                    })
                    continue
                if isinstance(target, ast.Subscript):
                    key = target.slice
                    self.writes.append({
                        "loc": loc_of(self.mod.module, node),
                        "base": self.expr(target.value),
                        "path": key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else None,
                        "from": src,
                    })
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
                self.flows.append({"from": src, "to": value_id, "kind": "property", "loc": at})
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

    for path in files:
        with open(path, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        trees.append((path, tree))
        mid = module_id(root, path)
        dotted = mid[:-3].replace("/", ".") if mid.endswith(".py") else mid
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
                for member in node.body:
                    if isinstance(member, FUNCTION_NODES):
                        fid = f"{mid}#{member.name}:{member.lineno}:{member.col_offset + 1}"
                        defs[f"{mid}:{node.name}.{member.name}"] = fid
                        # And by the name an importer would use, so `Student.create(...)`
                        # in another file resolves to the method rather than stopping at
                        # the class.
                        defs[f"import:{dotted}.{node.name}.{member.name}"] = fid

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

    templates = index_templates(root)

    modules, functions, entry_points = [], [], []
    for path, tree in trees:
        lowerer = ModuleLowerer(root, path, tree, defs, templates, resource_paths)
        lowerer.lower()
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
                "frameworkModels": ["flask", "flask-appbuilder", "fastapi"],
            },
        },
        "modules": modules,
        "functions": functions,
        "entryPoints": entry_points,
    }
