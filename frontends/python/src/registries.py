"""Route declarations that reach `urlpatterns` through something other than a literal.

A URLconf reader that matches `path(<literal>, <view>)` reads every Django application
that writes its routes down. Four idioms do not write them down, and each was measured
enumerating almost nothing:

    django-oscar   219 declared routes, 30 enumerated (14%)
    netbox         532 declared routes, 128 enumerated (24%)
    wagtail        220 walked registrations, 88 producing an entry point (40%)

DefectDojo, Django with DRF, enumerates at 108% against the same count, so no one of these
gaps is "Django". Each is one specific way of getting a list of registrations into
`urlpatterns` without the registration and the handler ever appearing in the same
expression.

**Shape 1 -- a method that composes with its parent.** An oscar application is a CLASS.
Every app contributes its routes by overriding `get_urls()`, the view is `self.<attr>`
resolved on the class, and the attribute is assigned in `ready()` from a two-string
loader call. There is no module-level `urlpatterns` in the entire package.

**Shape 2 -- a decorator registry read back at URL-build time.** A netbox view binds
itself to a model with `@register_model_view(Region, 'edit')` and `dcim/urls.py` asks for
the same key with `include(get_model_urls('dcim', 'region'))`. The route-to-view binding
is decorator to registry to call and is never written as a literal.

**Shape 3 -- a hook registry keyed by a string.** Nine of wagtail's applications write
`@hooks.register("register_admin_urls")` on a function returning routes, and
`wagtail/admin/urls/__init__.py` splices what each returns with
`for fn in hooks.get_hooks("register_admin_urls"): urlpatterns += fn()`. What travels
between the two is a function's RETURN VALUE, which no `include()` names.

**Shape 4 -- a view named by a string key.** 34 of `wagtail/admin/urls/pages.py`'s 35
registrations are `page_viewset_registry.as_view("edit", page_id_kwarg="page_id")`: the
address is a literal and the class is three hops away, through a dispatch table, a
property, and a class attribute in a third file.

**Shape 5 -- a viewset mounted at a prefix nothing writes down.** NOT BUILT; the
withdrawal and its numbers are recorded below, beside the shapes that are.

What all four need is the same thing and it is a LOOKUP, not an evaluation: the
declarations are all present in the source, addressed by a key one site writes and another
site reads. This module reads the keys and matches them. It computes no route text and builds no
entry point -- `lower.py` owns both, and this file is the layer below it, so it can be
read and tested as a question about the program rather than about the IR.

Ambiguity resolves to NOTHING here, everywhere, on purpose. An entry point is what
anchors a finding, and these findings are sent to maintainers: a route bound to the wrong
handler is a claim about an address that does not exist, which is worse than the gap it
was meant to close. Every lookup below therefore drops a key that resolves two ways.
"""

from __future__ import annotations

import ast

# How deep a base chain is followed. The same bound `declarative.py` uses, for the same
# reason: an application's config classes inherit three or four deep and nothing real goes
# further, while an unbounded walk over a cyclic name graph does not terminate.
MAX_BASE_DEPTH = 8

# The registrars a route declaration is written with. Duplicated from `lower.py` rather
# than imported, so this module stays the layer BELOW the lowerer and the two cannot form
# an import cycle.
REGISTRARS = frozenset({"path", "re_path", "url"})


def class_name_of(node: ast.AST) -> str:
    """The bare class name an expression reaches, written either way.

    `Region` and `dcim.models.Region` are one class named twice. The module half is
    dropped deliberately: which file a name reaches is a question about the importing
    module's own table, and the answer this module needs -- which class -- is the same
    either way.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _bool(node: ast.AST | None, default: bool) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return default


def _arg(call: ast.Call, index: int, name: str) -> ast.AST | None:
    """One argument of a call, written positionally or by keyword.

    The same reading `django_call_args` makes one level up, and for the same measured
    reason: a project that names its arguments and a project that does not are writing the
    same registration, and reading only one spelling drops the other project's whole
    surface.
    """
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return call.args[index] if len(call.args) > index else None


# --- Shape 2: a decorator registry -------------------------------------------
#
# `@register_model_view(Region, 'edit')` in `dcim/views.py` and
# `include(get_model_urls('dcim', 'region'))` in `dcim/urls.py` name one key from two
# files. Matching them needs the app label of the MODEL, which the decorator does not
# write: netbox's own decorator reads `model._meta.app_label`, and the label Django puts
# there is the package the model's module lives in.

DECORATOR = "register_model_view"
REGISTRY_READER = "get_model_urls"

# The module a Django app declares its models in. `dcim/models/sites.py` and
# `dcim/models.py` are one convention written two ways, and the component BEFORE it is the
# app label Django derives when the config does not override it.
MODELS_MODULE = "models"


class ModelViewRegistration:
    """One `@register_model_view(...)`, as the pair of facts a URL build reads back."""

    __slots__ = ("app_label", "model_name", "url_path", "detail", "module", "class_name")

    def __init__(self, app_label: str, model_name: str, url_path: str, detail: bool,
                 module: str, class_name: str):
        self.app_label = app_label
        self.model_name = model_name
        # What the registry appends under the mount: netbox writes `f"{path}/"` when the
        # registration named one and the empty string when it did not, and the empty one is
        # the list or detail view of the model itself.
        self.url_path = url_path
        self.detail = detail
        self.module = module
        self.class_name = class_name

    @property
    def key(self) -> tuple[str, str]:
        return (self.app_label, self.model_name)


class ModelViewRegistry:
    """Every view a decorator bound to a model, indexed by the key a URLconf asks with.

    Two indexes and one join. `_model_apps` answers "which Django app is this model in",
    which is the half the decorator leaves implicit; `by_key` answers "which views did
    anything bind to that app's model", which is what `get_model_urls` asks for.

    A model name that two apps both define resolves to NOTHING rather than to both. The
    cost is a model's whole tab set missing from the surface; the alternative is every one
    of those tabs claimed at an address in the wrong application.
    """

    def __init__(self, modules: list[tuple[str, ast.Module]]):
        self._model_apps = _model_app_labels(modules)
        self.by_key: dict[tuple[str, str], list[ModelViewRegistration]] = {}
        for module, tree in modules:
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    self._read_class(module, node)

    def _read_class(self, module: str, node: ast.ClassDef) -> None:
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            if class_name_of(dec.func) != DECORATOR or not dec.args:
                continue
            reg = self._registration(module, node, dec)
            if reg is not None:
                self.by_key.setdefault(reg.key, []).append(reg)

    def _registration(self, module: str, node: ast.ClassDef,
                      dec: ast.Call) -> ModelViewRegistration | None:
        model = class_name_of(dec.args[0])
        if not model:
            # `@register_model_view(self.model, ...)` or a name built at run time. There is
            # no key to match and inventing one would bind a route to a guess.
            return None
        apps = self._model_apps.get(model)
        if apps is None or len(apps) != 1:
            return None
        # `name` defaults to '' and `path` defaults to `name` -- the decorator's own
        # defaults, which is what decides the address when a registration writes neither.
        # A name COMPUTED rather than written produces an address that is not readable.
        name_node = _arg(dec, 1, "name")
        name = "" if name_node is None else _string(name_node)
        if name is None:
            return None
        path_node = _arg(dec, 2, "path")
        url_path = name if path_node is None else _string(path_node)
        if url_path is None:
            return None
        detail = _bool(_arg(dec, 3, "detail"), True)
        return ModelViewRegistration(
            next(iter(apps)), model.lower(), f"{url_path}/" if url_path else "",
            detail, module, node.name)

    def read(self, call: ast.Call) -> list[ModelViewRegistration] | None:
        """The views a `get_model_urls('dcim', 'region', detail=False)` call returns.

        None when this call is not one, or names a key with nothing under it, or names it
        with anything other than two literals -- the registry is keyed by strings and a
        key that is not written down cannot be looked up.
        """
        if class_name_of(call.func) != REGISTRY_READER:
            return None
        app_label = _string(_arg(call, 0, "app_label"))
        model_name = _string(_arg(call, 1, "model_name"))
        if app_label is None or model_name is None:
            return None
        detail = _bool(_arg(call, 2, "detail"), True)
        found = self.by_key.get((app_label, model_name.lower()))
        if not found:
            return None
        return [reg for reg in found if reg.detail == detail]


def _model_app_labels(modules: list[tuple[str, ast.Module]]) -> dict[str, set[str]]:
    """Model class name -> the Django app label(s) it is defined under.

    Django derives a model's app label from the package its `models` module lives in, and
    that package name is the only place the label is written when the config does not
    override it. Read from the FILE PATH for that reason, and only for classes that sit in
    a models module: a form, a table and a filterset routinely share a model's name, and a
    name index over the whole program would answer with whichever the walk reached first.

    A `class Meta: app_label = "x"` overrides the derivation, because that is what it does
    in Django.
    """
    out: dict[str, set[str]] = {}
    for module, tree in modules:
        derived = _app_label_of_module(module)
        if derived is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            out.setdefault(node.name, set()).add(_meta_app_label(node) or derived)
    return out


def _app_label_of_module(module: str) -> str | None:
    """`dcim/models/sites.py` and `dcim/models.py` -> `dcim`; anything else -> None.

    The FIRST `models` component and not the last, because a models package is free to
    hold a module of the same name: netbox writes `extras/models/models.py`, and scanning
    from the end read its app label as `models` and filed 73 registrations under a key no
    URLconf asks with. The package is what Django looks at, and the package is the outer
    one.
    """
    parts = module[:-3].split("/") if module.endswith(".py") else module.split("/")
    for index in range(1, len(parts)):
        if parts[index] == MODELS_MODULE:
            return parts[index - 1]
    return None


def _meta_app_label(node: ast.ClassDef) -> str | None:
    """`class Meta: app_label = "x"` -- Django's own override of the derived label."""
    for member in node.body:
        if not isinstance(member, ast.ClassDef) or member.name != "Meta":
            continue
        for stmt in member.body:
            if not isinstance(stmt, ast.Assign):
                continue
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id == "app_label":
                    return _string(stmt.value)
    return None


# --- Shape 1: routes a method returns ----------------------------------------
#
# An oscar application declares its routes inside `get_urls()` on an AppConfig subclass,
# points each one at `self.<attr>`, and is mounted by LABEL from another config's
# `get_urls()`. Nothing in that chain is a literal at the point where it is read, and every
# link of it is written down somewhere else in the program.

# What a config attribute can hold that this reader cares about.
ATTR_VIEW = "view"          # `self.detail_view = get_class("catalogue.views", "Detail")`
ATTR_APP = "appconfig"      # `self.catalogue_app = apps.get_app_config("catalogue")`

APP_LOOKUP = "get_app_config"


class ConfigClass:
    """One class that declares routes in a method, with what its attributes hold.

    Recognised by SHAPE and not by base: a config that registers routes is a class with a
    `path()` call inside a method, and requiring `AppConfig` in the bases would mean
    resolving a base name to a framework this frontend does not read.
    """

    __slots__ = ("module", "name", "bases", "label", "attrs", "registrations")

    def __init__(self, module: str, node: ast.ClassDef):
        self.module = module
        self.name = node.name
        self.bases = [class_name_of(b) for b in node.bases if class_name_of(b)]
        self.attrs: dict[str, tuple[str, str]] = {}
        self.registrations: list[ast.Call] = []
        self.label = _config_label(node)
        self._read(node)

    def _read(self, node: ast.ClassDef) -> None:
        for member in node.body:
            # A class-level `detail_view = ProductDetailView` is the same declaration the
            # `ready()` body below writes, one indent out.
            if isinstance(member, ast.Assign):
                for target in member.targets:
                    if isinstance(target, ast.Name):
                        self._bind(target.id, member.value)
            elif isinstance(member, ast.AnnAssign) and isinstance(member.target, ast.Name):
                if member.value is not None:
                    self._bind(member.target.id, member.value)
        for child in ast.walk(node):
            # `self.detail_view = ...` anywhere in the class. Django's own place for this
            # is `ready()`, which the framework calls before any URLconf is built, so an
            # attribute assigned there is as much a declaration as a class-level one.
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if (isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == "self"):
                        self._bind(target.attr, child.value)
            elif (isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
                    and child.func.id in REGISTRARS):
                self.registrations.append(child)

    def _bind(self, name: str, value: ast.AST) -> None:
        """What one attribute holds, when it holds something a route can be built from."""
        held = _attribute_value(value)
        if held is not None:
            # First write wins, which is the order a reader resolves them in and the order
            # `ready()` runs. A second binding of the same name is a reassignment this
            # module cannot order against the first, so it is not allowed to overwrite one.
            self.attrs.setdefault(name, held)


def _attribute_value(node: ast.AST) -> tuple[str, str] | None:
    """The declaration behind a config attribute, or None where there is not one.

    Three spellings and no more. `get_class("catalogue.views", "ProductDetailView")` is
    oscar's own loader and the shape is general -- a call whose LAST string argument names
    a class in the program; `apps.get_app_config("catalogue")` is Django's own registry
    lookup; and a bare name is the class itself.
    """
    if isinstance(node, ast.Call):
        if class_name_of(node.func) == APP_LOOKUP and node.args:
            label = _string(node.args[0])
            return (ATTR_APP, label) if label else None
        strings = [s for s in (_string(a) for a in node.args) if s is not None]
        # A loader call names the module first and the class last, which is the signature
        # of every dynamic class loader written for Django. Only the class half is used:
        # the module half is a label the loader resolves against a search path this
        # frontend does not have, and the class name is resolved program-wide -- the same
        # looseness every registration lookup in this frontend already accepts.
        if len(strings) >= 2 and strings[-1][:1].isupper():
            return (ATTR_VIEW, strings[-1])
        return None
    if isinstance(node, ast.Name) and node.id[:1].isupper():
        return (ATTR_VIEW, node.id)
    if isinstance(node, ast.Attribute) and node.attr[:1].isupper():
        return (ATTR_VIEW, node.attr)
    return None


def _config_label(node: ast.ClassDef) -> str | None:
    """The label an app is registered under, explicit or derived.

    Django's rule, because Django's registry is what `get_app_config` reads: an explicit
    `label` wins, and without one the label is the last component of `name`.
    """
    label = None
    dotted = None
    for member in node.body:
        if not isinstance(member, ast.Assign):
            continue
        for target in member.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id == "label":
                label = _string(member.value) or label
            elif target.id == "name":
                dotted = _string(member.value) or dotted
    if label:
        return label
    return dotted.rsplit(".", 1)[-1] if dotted else None


class ConfigRegistry:
    """Every route-declaring config class, and every mount written outside one.

    Classes are kept individually and never merged by label, and that is what makes the
    composition come out right. django-oscar splits one app across `CatalogueOnlyConfig`
    and `CatalogueReviewsOnlyConfig`, both labelled `catalogue`, and ships
    `CatalogueConfig(CatalogueOnlyConfig, CatalogueReviewsOnlyConfig)` as the app that is
    actually installed -- so `super().get_urls()` inside the first reaches the second
    through the MRO, and the routes the running application serves are the union of both.
    Reading each declaring class in turn and resolving its mount by label produces that
    union without anything having to model the MRO.
    """

    def __init__(self, modules: list[tuple[str, ast.Module]]):
        self.classes: list[ConfigClass] = []
        # `path('', include(apps.get_app_config('oscar').urls[0]))` -- the root URLconf
        # mounting the whole shop. Collected apart from the class-owned mounts because it
        # has no `self` to resolve an attribute against: the label is written out.
        self.module_level_mounts: list[tuple[str, str]] = []
        by_name: dict[str, list[ConfigClass]] = {}
        for module, tree in modules:
            in_class: set[int] = set()
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                cls = ConfigClass(module, node)
                in_class.update(id(call) for call in cls.registrations)
                if not cls.registrations and not cls.attrs:
                    continue
                self.classes.append(cls)
                by_name.setdefault(cls.name, []).append(cls)
            self._read_module_mounts(tree, in_class)
        self.by_name = by_name

    def _read_module_mounts(self, tree: ast.Module, in_class: set[int]) -> None:
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in REGISTRARS):
                continue
            if id(node) in in_class:
                continue
            # Read by keyword as well as by position, for the reason `django_call_args`
            # is: `path(route=..., view=...)` is how a great many projects write the same
            # registration, and reading one spelling drops the other project's mount.
            route = _string(_arg(node, 0, "route"))
            target = _arg(node, 1, "view")
            if route is None or target is None:
                continue
            if (isinstance(target, ast.Call) and class_name_of(target.func) == "include"
                    and target.args):
                target = target.args[0]
            label = self.mounted_label(None, target)
            if label is not None:
                self.module_level_mounts.append((route, label))

    def declaring(self) -> list[ConfigClass]:
        """The classes that actually declare a route, which is what is worth walking."""
        return [c for c in self.classes if c.registrations]

    def attribute(self, cls: ConfigClass, name: str) -> tuple[str, str] | None:
        """What `self.<name>` holds on this class, its own bases included.

        The base chain is walked for the reason `declarative.py` walks it for permission
        classes: an application splits the declaration and its use across the chain on
        purpose -- oscar's dashboard configs assign in `ready()` on the class and register
        in `get_urls()` on the same class, but a project extending oscar overrides one half
        and inherits the other.
        """
        for facts in self.chain(cls):
            held = facts.attrs.get(name)
            if held is not None:
                return held
        return None

    def chain(self, cls: ConfigClass) -> list[ConfigClass]:
        """The class and everything it inherits, nearest first and bounded."""
        out: list[ConfigClass] = []
        seen: set[str] = set()
        pending: list[tuple[ConfigClass, int]] = [(cls, 0)]
        while pending:
            current, depth = pending.pop(0)
            key = f"{current.module}:{current.name}"
            if key in seen or depth > MAX_BASE_DEPTH:
                continue
            seen.add(key)
            out.append(current)
            for base in current.bases:
                # By NAME and program-wide, which is the resolution every registration
                # lookup in this frontend already uses. A base defined in a framework is
                # simply not found, and a base this program does define is.
                for facts in self.by_name.get(base, []):
                    pending.append((facts, depth + 1))
        return out

    def label_of(self, cls: ConfigClass) -> str | None:
        """The label this class is registered under, inherited if it does not say.

        A composite that names neither `label` nor `name` takes them from the config it
        extends, exactly as Django's own `AppConfig` does.
        """
        for facts in self.chain(cls):
            if facts.label:
                return facts.label
        return None

    def mounted_label(self, cls: ConfigClass | None, node: ast.AST) -> str | None:
        """The app label a mount expression names, or None where it names no app.

        `self.catalogue_app.urls`, `self.catalogue_app.urls[0]` and
        `apps.get_app_config('oscar').urls[0]` are one mount written three ways. The
        `.urls` is what makes it one: an app config holds many attributes and only that
        property is a URLconf.
        """
        node = _unsubscript(node)
        if not isinstance(node, ast.Attribute) or node.attr != "urls":
            return None
        holder = node.value
        if (isinstance(holder, ast.Attribute) and isinstance(holder.value, ast.Name)
                and holder.value.id == "self"):
            held = self.attribute(cls, holder.attr) if cls is not None else None
            return held[1] if held and held[0] == ATTR_APP else None
        held = _attribute_value(holder)
        return held[1] if held and held[0] == ATTR_APP else None


def _unsubscript(node: ast.AST) -> ast.AST:
    """`x.urls[0]` -> `x.urls`. An app config's `urls` is a three-tuple and the first
    element is the pattern list; the other two are namespaces, which are names and not
    paths."""
    return node.value if isinstance(node, ast.Subscript) else node


# --- Shape 3: a hook registry keyed by a string ------------------------------
#
# `@hooks.register("register_admin_urls")` in nine of wagtail's applications and
# `for fn in hooks.get_hooks("register_admin_urls"): urlpatterns += fn()` in
# `wagtail/admin/urls/__init__.py`. The registration and the list it lands in name one
# key from two files, and nothing in between is a route expression: the routes are the
# RETURN VALUE of a function no caller in the source ever names.
#
# This is the shape `register_model_view` above already answers, one level up: there the
# key bound a view to a model, here it binds a whole list of registrations to the list
# that splices it. Measured on wagtail: thirteen registrations sit inside these functions
# and every one of them is an `include(...)`, so the count they contribute is zero and the
# ADDRESS they contribute is everything. Without the key, the admin's documents, images,
# forms, settings, redirects, search-promotions, embeds and styleguide URLconfs were
# enumerated at `/documents/`, `/images/`, `/forms/` and the rest rather than under
# `/admin/` -- and `/documents/<int:document_id>/...` is a path wagtail really does serve,
# from `wagtail/documents/urls.py`, with a different view. Entry points claimed at an
# address that exists and answers with something else are the worst kind an anchor can be.

# The decorator half. `register` is a common word, which is why nothing here fires on it
# alone: a key produces an edge only when a `get_hooks` call names the SAME key, so the
# join and not the spelling is what decides.
HOOK_DECORATOR = "register"

# The read-back half. Distinctive, and the reason this reader can be keyed on a name at
# all -- the same judgement `get_model_urls` above is read under.
HOOK_READER = "get_hooks"

# What a loop body has to do with a hook's return value for it to be routes. `+=` is how
# Django's own documentation writes it and how wagtail does; `.extend()` is the same
# statement spelled as a call.
HOOK_SPLICES = frozenset({"extend"})


def hook_list_name(key: str, function: str) -> str:
    """The name the routes one hook function returns are carried under.

    A synthetic list name, because the routes are inside a function and a function is not
    a list -- but every other mount in this frontend is `(module, list name)`, and giving
    the return value a name lets the same graph walk resolve it. It never leaves the
    frontend: only the prefix it resolves to reaches the IR.
    """
    return f"<hook {key}:{function}>"


class HookRouteRegistry:
    """Route lists a string key binds to the `urlpatterns` that splices them.

    Two indexes and one join, exactly as `ModelViewRegistry` above. `providers` answers
    "which functions did anything register under this key"; `consumers` answers "which
    list reads that key back and splices what it returns". A key present on only one side
    binds nothing, which is what makes the pair safe to key on a name as ordinary as
    `register`: wagtail registers under twenty-odd hook names and only `register_admin_urls`
    has a URLconf reading it back, so only that one moves a route.
    """

    __slots__ = ("providers", "consumers")

    def __init__(self, modules: list[tuple[str, ast.Module]]):
        self.providers: dict[str, list[tuple[str, str]]] = {}
        self.consumers: dict[str, list[tuple[str, str]]] = {}
        for module, tree in modules:
            for stmt in tree.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for key in _hook_keys(stmt):
                        self.providers.setdefault(key, []).append((module, stmt.name))
            bound = _module_level_names(tree)
            for node in ast.walk(tree):
                if not isinstance(node, ast.For):
                    continue
                key = _hook_reader_key(node.iter)
                if key is None:
                    continue
                for name in _spliced_into(node.body):
                    # A name this module does not bind at module level is not a URLconf of
                    # this module: it is a local of whatever function the loop sits in, and
                    # the mount graph is keyed on module-level lists.
                    if name in bound:
                        self.consumers.setdefault(key, []).append((module, name))

    def lists_of(self, module: str) -> dict[str, str]:
        """Function name -> the synthetic list its registrations belong to, in one module.

        Only for keys something reads back. A hook nothing splices contributes no mount,
        so attributing its registrations to a list of their own would move where they are
        served for no reason -- they keep the answer the module already gave.
        """
        out: dict[str, str] = {}
        for key, registered in self.providers.items():
            if key not in self.consumers:
                continue
            for owner, function in registered:
                if owner == module:
                    out[function] = hook_list_name(key, function)
        return out

    def edges(self) -> list[tuple[tuple[str, str], str, str, str]]:
        """((provider module, its hook list), route, consumer module, consumer list).

        The route is always empty: `urlpatterns += fn()` splices the list in at the path
        the consuming list is already served at, and each registration inside carries its
        own route from there.
        """
        out: list[tuple[tuple[str, str], str, str, str]] = []
        for key, registered in self.providers.items():
            for module, name in self.consumers.get(key, ()):
                for owner, function in registered:
                    out.append(((owner, hook_list_name(key, function)), "", module, name))
        return out


def _hook_keys(node: ast.AST) -> list[str]:
    """The keys a function is registered under, out of the decorators it carries.

    `@hooks.register("register_admin_urls")` and `@register("register_admin_urls")` are
    one registration written two ways. A key that is not a literal is not read: a name
    computed at import time is a key this frontend cannot look up, and guessing one binds
    a list of routes to a list that does not splice it.
    """
    found: list[str] = []
    for dec in getattr(node, "decorator_list", ()):
        if not isinstance(dec, ast.Call) or class_name_of(dec.func) != HOOK_DECORATOR:
            continue
        key = _string(_arg(dec, 0, "hook_name"))
        # `hooks.register("name", fn)` passes the function as its second argument and is
        # not decorating anything. Used as a decorator it takes the key alone.
        if key is not None and len(dec.args) < 2:
            found.append(key)
    return found


def _hook_reader_key(node: ast.AST) -> str | None:
    """`hooks.get_hooks("register_admin_urls")` -> the key, or None where there is none."""
    if not isinstance(node, ast.Call) or class_name_of(node.func) != HOOK_READER:
        return None
    return _string(_arg(node, 0, "hook_name"))


def _spliced_into(body: list[ast.stmt]) -> set[str]:
    """The module-level lists a loop body appends a hook's return value to.

    Walked rather than scanned, because the statement that splices is routinely nested:
    wagtail writes `urls = fn()`, then `if urls:`, then `urlpatterns += urls`, and the
    `+=` is two blocks in.
    """
    found: set[str] = set()
    for stmt in body:
        for node in ast.walk(stmt):
            if (isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add)
                    and isinstance(node.target, ast.Name)):
                found.add(node.target.id)
            elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in HOOK_SPLICES
                    and isinstance(node.func.value, ast.Name)):
                found.add(node.func.value.id)
    return found


# --- Shape 4: a view named by a string key -----------------------------------
#
# wagtail's page URLconf writes 37 of its registrations as
#
#     path("<int:page_id>/edit/", page_viewset_registry.as_view("edit", page_id_kwarg="page_id"))
#
# The ADDRESS there is a literal and already resolves correctly. The handler is four hops
# away, and every hop is written down somewhere else in the program:
#
#     "edit"                                  the key the URLconf writes
#     views = {"edit": self.edit_view}        a dispatch table on the viewset class
#     def edit_view(self): return self.construct_view(self.edit_view_class)
#     edit_view_class = EditView              and that module imports EditView by name
#
# So the join is the same one the two registries above make -- a key one site writes and
# another site reads -- with an attribute chain on the far side of it. Nothing is
# evaluated: each hop is a lookup in a class body, and a hop that does not resolve to a
# class this program defines resolves to NOTHING. That matters more here than anywhere
# else in this file, because the address is already right: a wrong handler at a right
# address is a finding a maintainer will go and look at and not find.

# How many entries a dict has to have before it is read as a dispatch table. One entry is
# any mapping at all; a table a URLconf dispatches through names the whole surface of a
# viewset.
VIEW_TABLE_MIN = 2

# How far an attribute chain is followed. wagtail's longest is three hops (key, property,
# class attribute) and the bound is stated rather than discovered, for the reason every
# other bound in this file is (ADR-003).
MAX_ATTR_HOPS = 8


class ViewSetClass:
    """One class, as the declarations a keyed view lookup reads.

    `attrs` merges the three places a class says what an attribute holds -- a class-level
    assignment, an assignment to `self` in a method Django calls before any URL is built,
    and a property that RETURNS the view. The last is what wagtail's viewsets are made of
    and is the one shape `ConfigClass` above does not read: oscar assigns its views and
    wagtail computes them, and both are declarations at the point a URLconf reads them.
    """

    __slots__ = ("module", "name", "bases", "attrs", "table")

    def __init__(self, module: str, node: ast.ClassDef):
        self.module = module
        self.name = node.name
        self.bases = [class_name_of(b) for b in node.bases if class_name_of(b)]
        self.attrs: dict[str, ast.AST] = {}
        self.table: dict[str, str] = {}
        for member in node.body:
            if isinstance(member, ast.Assign):
                for target in member.targets:
                    if isinstance(target, ast.Name):
                        self.attrs.setdefault(target.id, member.value)
            elif isinstance(member, ast.AnnAssign) and isinstance(member.target, ast.Name):
                if member.value is not None:
                    self.attrs.setdefault(member.target.id, member.value)
            elif isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                held = _returned_value(member)
                if held is not None:
                    self.attrs.setdefault(member.name, held)
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if (isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == "self"):
                        self.attrs.setdefault(target.attr, child.value)
            elif isinstance(child, ast.Dict):
                self.table.update(_dispatch_table(child))


def _returned_value(node: ast.AST) -> ast.AST | None:
    """What a method hands back, when it hands back one expression and no other.

    Only the method's OWN returns: a nested function's return is that function's answer,
    not this one's. A method with two of them holds two things and this reader does not
    know which -- ambiguity resolves to nothing, here as everywhere in this file.
    """
    found: list[ast.AST] = []
    pending: list[ast.AST] = list(getattr(node, "body", ()))
    while pending:
        current = pending.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(current, ast.Return):
            if current.value is not None:
                found.append(current.value)
            continue
        pending.extend(ast.iter_child_nodes(current))
    return found[0] if len(found) == 1 else None


def _dispatch_table(node: ast.Dict) -> dict[str, str]:
    """`{"edit": self.edit_view, ...}` -- a string key to an attribute of the same class.

    Recognised by SHAPE and not by the name the dict is bound to, because it is bound to
    a property in wagtail and could be bound to anything elsewhere. Every key a literal
    string and every value an attribute of `self`: that is a dispatch table and very
    little else is.
    """
    out: dict[str, str] = {}
    if len(node.keys) < VIEW_TABLE_MIN:
        return out
    for key, value in zip(node.keys, node.values):
        name = _string(key)
        if name is None:
            return {}
        if not (isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name)
                and value.value.id == "self"):
            return {}
        out[name] = value.attr
    return out


class ViewKeyRegistry:
    """The view class a program binds to a string key, or nothing where two do.

    A key declared by two classes resolves to NEITHER. The cost is one viewset's routes
    missing a handler; the alternative is every one of them bound to whichever class the
    walk reached first, at an address the URLconf states plainly and a maintainer will
    open.
    """

    __slots__ = ("by_key", "by_name")

    def __init__(self, modules: list[tuple[str, ast.Module]]):
        holders: dict[str, list[ViewSetClass]] = {}
        self.by_name: dict[str, list[ViewSetClass]] = {}
        for module, tree in modules:
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                facts = ViewSetClass(module, node)
                if not facts.attrs and not facts.table:
                    continue
                self.by_name.setdefault(facts.name, []).append(facts)
                for key in facts.table:
                    holders.setdefault(key, []).append(facts)
        self.by_key = {key: found[0] for key, found in holders.items() if len(found) == 1}

    def resolve(self, key: str) -> tuple[str, ast.AST] | None:
        """(module that wrote the reference, the class reference) for one dispatch key."""
        facts = self.by_key.get(key)
        if facts is None:
            return None
        return self._reference(facts, facts.table[key], 0)

    def _reference(self, root: ViewSetClass, attr: str,
                   depth: int) -> tuple[str, ast.AST] | None:
        """What `self.<attr>` holds, resolved on the class and its bases nearest first.

        Always from the ROOT class, at every hop. `PageListingViewSet.index_view` returns
        `self.construct_view(self.index_view_class)` and `PageViewSet` overrides
        `index_view_class` -- which is the answer Python gives, because the attribute is
        resolved on the instance's own class and not on the one that wrote the property.
        """
        if depth > MAX_ATTR_HOPS:
            return None
        for facts in self.chain(root):
            held = facts.attrs.get(attr)
            if held is not None:
                return self._interpret(root, facts, held, depth)
        return None

    def _interpret(self, root: ViewSetClass, facts: ViewSetClass, node: ast.AST,
                   depth: int) -> tuple[str, ast.AST] | None:
        """One declaration, read as the class behind it.

        Four spellings and no more: another attribute of the same object, a call that
        wraps one (`self.construct_view(self.edit_view_class, **kwargs)`), an `as_view()`
        on a class, and the class itself. Anything else is a view this reader cannot name,
        and naming it anyway is the wrong-handler-at-a-right-address case above.
        """
        if depth > MAX_ATTR_HOPS:
            return None
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id == "self"):
            return self._reference(root, node.attr, depth + 1)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "as_view":
                return self._interpret(root, facts, node.func.value, depth + 1)
            # A wrapper takes the view it builds as its first argument, which is the
            # signature of every `construct_view`-style helper. A keyword-only call names
            # nothing this reader can follow.
            if node.args:
                return self._interpret(root, facts, node.args[0], depth + 1)
            return None
        if isinstance(node, (ast.Name, ast.Attribute)) and class_name_of(node)[:1].isupper():
            # Returned with the module that WROTE it: the reference is resolved against
            # that module's imports, not against the URLconf's, and the two are never the
            # same file.
            return (facts.module, node)
        return None

    def chain(self, cls: ViewSetClass) -> list[ViewSetClass]:
        """The class and everything it inherits, nearest first and bounded.

        By bare base name and program-wide, the resolution every registration lookup in
        this frontend uses. A base defined in a framework is simply not found; a base this
        program does define is.
        """
        out: list[ViewSetClass] = []
        seen: set[str] = set()
        pending: list[tuple[ViewSetClass, int]] = [(cls, 0)]
        while pending:
            current, depth = pending.pop(0)
            key = f"{current.module}:{current.name}"
            if key in seen or depth > MAX_BASE_DEPTH:
                continue
            seen.add(key)
            out.append(current)
            for base in current.bases:
                for facts in self.by_name.get(base, []):
                    pending.append((facts, depth + 1))
        return out


# --- Shape 5: a viewset mounted at a prefix nothing writes down -- NOT BUILT ---
#
# WITHDRAWN AFTER MEASUREMENT, and the numbers are here so the next attempt starts from
# them rather than from the idea. wagtail declares 287 route registrations that this
# frontend's AST can see; 220 of them are non-include registrations in production modules
# and are what `django_entry_points` walks. Before this file's shapes 3 and 4, 88 of the
# 220 produced an entry point; after them, 138 do. Of the 82 that still produce nothing,
# 46 are one shape and it is this one:
#
#     class ModelViewSet(ViewSet):
#         index_view_class = generic.IndexView
#         @property
#         def index_view(self): return self.construct_view(self.index_view_class, ...)
#         def get_urlpatterns(self):
#             return [path("", self.index_view, name="index"), ...]
#
# The HANDLER side of that is already readable -- it is shape 4's attribute chain with no
# dispatch table in front of it. What is not readable is the ADDRESS. A viewset's routes
# are mounted by `ViewSetRegistry.get_urlpatterns`, which writes
# `path(f"{viewset.url_prefix}/", include(...))` over every INSTANCE registered under the
# `register_admin_viewset` hook -- so the prefix is a keyword argument on a constructor
# call inside another hook function, and `url_prefix` falls back to `name`, which falls
# back to a class attribute. Two of wagtail's registered viewsets write it as a literal
# (`SiteViewSet("wagtailsites", url_prefix="sites")`); the largest group by far does not:
# 26 of the 46 are `SnippetViewSet.get_urlpatterns`, mounted once per snippet model at a
# prefix built at run time from the model's app label and model name, which is written
# nowhere in the source.
#
# So enumerating them means either inventing a prefix or serving them at the empty one,
# and `path("", self.index_view)` at the empty prefix claims the site root -- an address
# that exists, that a maintainer will open, and that answers with the admin home. The
# whole file's rule applies: AMBIGUITY RESOLVES TO NOTHING. These 46 registrations are
# left unenumerated, deliberately, and the gap is stated here rather than filled with a
# guess. What would change the answer is a reading of the registry's own mount -- the
# `f"{viewset.url_prefix}/"` inside `ViewSetRegistry.get_urlpatterns` joined to the
# instances the `register_admin_viewset` hook returns -- which is a fourth join and not a
# variation on shape 4.


def _module_level_names(tree: ast.Module) -> set[str]:
    """The names a module binds at its top level, which is where a URLconf lives."""
    found: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    found.add(target.id)
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            found.add(stmt.target.id)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            found.add(stmt.target.id)
    return found
