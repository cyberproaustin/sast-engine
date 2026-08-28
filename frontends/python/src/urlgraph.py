"""Where a URLconf is served, composed across the modules that assemble it.

`urlpatterns` is a VALUE, not a declaration. Django reads it out of whichever module an
`include()` names, and real applications hand `include()` something that is not a literal
list: a dotted string, a module they imported under an alias, or a package whose
`__init__` re-exports the lists of its submodules. A frontend that reads `urlpatterns`
only where it is written literally enumerates the registrations and gives them the wrong
path -- or, where the view class travels through the same kind of re-export, enumerates
nothing at all.

Measured on ten applications the engine had not seen: plane declares 399 routes and 51
entry points were enumerated (13%), wagtail 352 against 199 (57%), netbox 532 against 128
(24%). DefectDojo, whose root URLconf mounts literal lists, enumerated 700 against 650 --
so the gap is not "Django", it is what happens when the list is not literal.

This module holds the part of that resolution that is pure data: a dotted name as an
application WRITES it, resolved to the file that holds it, and the mount graph solved for
the absolute path of every list. The AST that produces the graph's edges stays in
`lower.py`, where the rest of the Django model is.

AMBIGUITY RESOLVES TO NOTHING. If a dotted name could name two modules, it names neither.
A phantom route is worse than a missing one: an entry point is what anchors a finding, so
a route at an address that does not exist attaches a judgement to something no maintainer
can go and look at.
"""

from __future__ import annotations

# A name that two files answer to. Kept as a value in the tables rather than deleting the
# key, so a later file cannot re-create an entry an earlier collision already ruled out.
AMBIGUOUS = object()

# The bounds on the walk, stated rather than left to be discovered (ADR-003).
#
# MAX_PREFIXES: a list mounted at more than sixteen paths contributes only the first
# sixteen. Versioned APIs mount one list three or four times, which is why the cap is not
# one -- keeping only the first mount left two thirds of one public API out of the surface.
#
# MAX_DEPTH: a chain of more than forty mounts stops and contributes the empty prefix, so
# the routes below it are still enumerated with a path that is short rather than dropped
# (ADR-009). No application in the batch nests deeper than six.
#
# Cycles: a URL graph can contain one -- a package whose submodule includes the package.
# A node reached while it is still being resolved contributes the empty prefix and the
# walk continues, so the graph is traversed once per node rather than once per path.
MAX_PREFIXES = 16
MAX_DEPTH = 40

# How far a re-export chain is followed. `from .a import X` in a package `__init__` that
# itself re-exports from `.b` is two hops; plane's views package is one. Bounded for the
# same reason the mount walk is.
MAX_HOPS = 8


def package_dotted(module: str) -> str | None:
    """The name an importer writes for a module id, or None when it is not a module.

    A package's `__init__.py` is written as the package: `plane.app.urls`, never
    `plane.app.urls.__init__`. Reading the file name literally is why the existing
    single-level prefix table never matched plane at all.
    """
    if not module.endswith(".py"):
        return None
    stem = module[:-3]
    if stem.endswith("/__init__"):
        stem = stem[: -len("/__init__")]
    return stem.replace("/", ".") if stem else None


class ModuleIndex:
    """A dotted module name as an application writes it, to the file that holds it.

    An application writes `include("plane.app.urls")` against ITS source root, and this
    engine is pointed at a repository root. plane's is `apps/api/`, so nothing in that
    application spells a module the way the frontend's own ids do -- which is why the
    lookup is by SUFFIX and not by equality. The exact name is tried first so a module
    that really is at the root wins over one that merely ends the same way.
    """

    def __init__(self, modules: list[str]) -> None:
        self._exact: dict[str, str | object] = {}
        self._suffix: dict[str, str | object] = {}
        for module in modules:
            dotted = package_dotted(module)
            if dotted is None:
                continue
            self._record(self._exact, dotted, module)
            parts = dotted.split(".")
            for cut in range(1, len(parts)):
                self._record(self._suffix, ".".join(parts[cut:]), module)

    @staticmethod
    def _record(table: dict[str, str | object], key: str, module: str) -> None:
        seen = table.get(key)
        if seen is None:
            table[key] = module
        elif seen is not module:
            table[key] = AMBIGUOUS

    def resolve(self, dotted: str) -> str | None:
        """The one module this name can mean, or None when it means none or several."""
        for table in (self._exact, self._suffix):
            found = table.get(dotted)
            if isinstance(found, str):
                return found
            if found is AMBIGUOUS:
                return None
        return None


class SymbolIndex:
    """A name as an importer writes it, resolved to the module that DEFINES it.

    `from plane.app.views import AnalyticsEndpoint` names a package whose `__init__` does
    `from .analytic.base import AnalyticsEndpoint`, and the class is three modules away
    from the name the URLconf wrote. Every one of plane's 397 route registrations reaches
    its view that way, and a lookup that stopped at the name as written found no class,
    no verbs, and therefore no entry point: all 31 http entry points the engine produced
    for plane came from the declarative fallback, at the class's NAME rather than at a path.
    """

    def __init__(self, index: ModuleIndex, imports: dict[str, dict[str, str]],
                 defined: dict[str, set[str]]) -> None:
        self.index = index
        self.imports = imports
        self.defined = defined

    def resolve(self, dotted: str) -> tuple[str, str] | None:
        """(module id, name) for a dotted symbol, following re-exports."""
        parts = dotted.split(".")
        # Longest module prefix first: `a.b.views.Detail` is the class `Detail` of module
        # `a.b.views` before it is anything of module `a.b`.
        for cut in range(len(parts) - 1, 0, -1):
            module = self.index.resolve(".".join(parts[:cut]))
            if module is None or len(parts) - cut != 1:
                continue
            found = self._follow(module, parts[cut], frozenset())
            if found is not None:
                return found
        return None

    def _follow(self, module: str, name: str, seen: frozenset) -> tuple[str, str] | None:
        if (module, name) in seen or len(seen) >= MAX_HOPS:
            return None
        if name in self.defined.get(module, ()):
            return (module, name)
        origin = self.imports.get(module, {}).get(name)
        if origin is None:
            return None
        parts = origin.split(".")
        if len(parts) < 2:
            return None
        target = self.index.resolve(".".join(parts[:-1]))
        if target is None:
            return None
        return self._follow(target, parts[-1], seen | {(module, name)})

    def patterns(self, dotted: str) -> tuple[str, str] | None:
        """(module id, list name) for whatever an `include()` was handed.

        The three shapes are one question. `include("plane.app.urls")` names a module and
        means its `urlpatterns`; `include(wagtailadmin_pages_urls)` on
        `from wagtail.admin.urls import pages as wagtailadmin_pages_urls` names a module
        the same way once the alias is undone; and `from .analytic import urlpatterns as
        analytic_urls` names a LIST inside one. Asking "is this a module?" first and "is
        this a name inside a module?" second separates them without either shape having
        to be recognised as itself.
        """
        module = self.index.resolve(dotted)
        if module is not None:
            return (module, "urlpatterns")
        return self.resolve(dotted)


class UrlGraph:
    """Every path a list of route declarations is served at.

    A registration's path is the route it writes, under the list it sits in, under the
    list THAT is mounted in, across as many modules as the application spread it over.
    plane writes each of those three joints in a different file: `plane/urls.py` mounts
    `"plane.app.urls"` at `api/`, that package's `__init__` splices in the `urlpatterns`
    of twenty-two submodules, and each submodule writes the routes. None of the three
    names the other two.
    """

    def __init__(self, mounts: dict[str, dict[str, list[tuple[str, str | None]]]],
                 edges: dict[tuple[str, str], list[tuple[str, str, str]]]) -> None:
        # module id -> list name -> [(route, the list the mounting call sits in)]
        self.mounts = mounts
        # (module id, list name) -> [(route, mounting module, the list the mount sits in)]
        self.edges = edges
        self._solved: dict[tuple[str, str], list[str]] = {}
        self._active: set[tuple[str, str]] = set()

    def prefixes(self, module: str, name: str | None) -> list[str]:
        """Every absolute path prefix the named list of this module is served under."""
        return self._walk(module, name or "urlpatterns", 0)

    def _walk(self, module: str, name: str, depth: int) -> list[str]:
        key = (module, name)
        if key in self._solved:
            return self._solved[key]
        # A cycle, or a chain past the stated bound. The empty prefix rather than no
        # route: a path that is short is worth far more than a route the surface does not
        # contain, and this is the same trade the unresolved-mount case has always made.
        if key in self._active or depth >= MAX_DEPTH:
            return [""]

        local = self.mounts.get(module, {}).get(name, ())
        incoming = self.edges.get(key, ())
        if not local and not incoming:
            # A list nothing mounts is served where the module's own `urlpatterns` is.
            # That is what the single-level prefix table did for every list in a file, and
            # it is the only answer available for a mount written over a setting.
            if name != "urlpatterns":
                return self._walk(module, "urlpatterns", depth + 1)
            return [""]

        self._active.add(key)
        found: list[str] = []
        for route, owner in local:
            self._extend(found, self._walk(module, owner or "urlpatterns", depth + 1), route)
        for route, source, owner in incoming:
            self._extend(found, self._walk(source, owner or "urlpatterns", depth + 1), route)
        self._active.discard(key)

        result = found or [""]
        self._solved[key] = result
        return result

    @staticmethod
    def _extend(found: list[str], bases: list[str], route: str) -> None:
        for base in bases:
            if len(found) >= MAX_PREFIXES:
                return
            if base + route not in found:
                found.append(base + route)
