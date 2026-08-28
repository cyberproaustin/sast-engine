"""Route declarations that reach `urlpatterns` through something other than a literal.

A URLconf reader that matches `path(<literal>, <view>)` reads every Django application
that writes its routes down. Two idioms do not write them down, and both were measured
enumerating almost nothing:

    django-oscar   219 declared routes, 30 enumerated (14%)
    netbox         532 declared routes, 128 enumerated (24%)

DefectDojo, Django with DRF, enumerates at 108% against the same count, so neither gap is
"Django". Each is one specific way of getting a list of registrations into `urlpatterns`
without the registration and the handler ever appearing in the same expression.

**Shape 1 -- a method that composes with its parent.** An oscar application is a CLASS.
Every app contributes its routes by overriding `get_urls()`, the view is `self.<attr>`
resolved on the class, and the attribute is assigned in `ready()` from a two-string
loader call. There is no module-level `urlpatterns` in the entire package.

**Shape 2 -- a decorator registry read back at URL-build time.** A netbox view binds
itself to a model with `@register_model_view(Region, 'edit')` and `dcim/urls.py` asks for
the same key with `include(get_model_urls('dcim', 'region'))`. The route-to-view binding
is decorator to registry to call and is never written as a literal.

What both need is the same thing and it is a LOOKUP, not an evaluation: the declarations
are all present in the source, addressed by a key one site writes and another site reads.
This module reads the keys and matches them. It computes no route text and builds no
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
            if id(node) in in_class or len(node.args) < 2:
                continue
            route = _string(node.args[0])
            if route is None:
                continue
            target = node.args[1]
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
