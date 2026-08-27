"""Template files: the half of a Flask application that actually writes the HTML.

A view is not Python, and for most of this project's life that meant it was not lowered at
all -- which put the most common form of cross-site scripting outside the engine's reach.
Every escaping decision a server-rendered application makes is made HERE, in a syntax the
language's parser has never heard of.

Jinja2 differs from the JavaScript engines in the direction that matters: autoescaping is
ON for the extensions Flask treats as markup, so `{{ x }}` is safe and only an explicit
`| safe` -- or a value already wrapped in `Markup` -- opts out. The filter is therefore the
whole of the judgement, and there is no one-character difference to miss.

What is extracted is deliberately small: for each interpolation, whether the engine escapes
it, and what it reads. An interpolation this file cannot read is skipped, which is a stated
miss rather than a guess (ADR-003).
"""

from __future__ import annotations

import os
import re

# Exactly the extensions Flask autoescapes, and no others.
#
# The list is not "every template" and not "every file under templates/". Flask's
# select_autoescape enables escaping for these and leaves it OFF everywhere else, so a
# `.j2` or a `.txt` template is one where `{{ x }}` is already unescaped -- and reporting
# those as scripting bugs would report every Ansible playbook and every generated
# configuration file in the tree. Their real risk is not markup and this engine does not
# claim to judge it.
MARKUP_EXTENSIONS = (".html", ".htm", ".xhtml", ".xml", ".svg")

SKIP_DIRECTORIES = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}

# An access path this frontend is willing to say it understands. `user.name`,
# `user["name"]`, `items[0].name` and `items[i].name` are reads of a field; `helper(user)`
# and `a if b else c` are not paths, and pretending they were would attach a finding to a
# value nobody can point at.
#
# A VARIABLE index counts for the same reason a numeric one does: `{{ rows[i].name }}`
# inside a loop is the shape every table in every application has, and refusing it meant
# refusing the most common place an interpolation appears.
_PATH_ONLY = re.compile(
    r"^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*|\[[\"'][^\"'\]]+[\"']\]|\[\d+\]|\[[A-Za-z_][\w]*\])*$"
)

# Values that are not reads of anything a render call supplied.
_NOT_A_READ = {"none", "true", "false", "loop", "self"}

# Bounded so a pathological file cannot make the scan quadratic: `"{{" * 100000` with no
# closing brace would otherwise rescan to the end of the file from every opener, and no
# real interpolation is anywhere near this long.
_INTERPOLATION = re.compile(r"\{\{(.{0,400}?)\}\}", re.S)
_RAW_OPEN = re.compile(r"\{%-?\s*raw\s*-?%\}")
_RAW_CLOSE = re.compile(r"\{%-?\s*endraw\s*-?%\}")
_AUTOESCAPE_OFF = re.compile(r"\{%-?\s*autoescape\s+(?:false|no|off|0)\s*-?%\}", re.I)
_STRING_ARG = re.compile(r"(['\"])(?:\\.|(?!\1)[^\\])*\1")
_SAFE_FILTER = re.compile(r"\|\s*safe\b")
_ESCAPE_FILTER = re.compile(r"\|\s*(?:e|escape|forceescape|urlencode)\b")
_MARKUP = re.compile(r"\bMarkup\s*\(")
_SUBSCRIPT = re.compile(r"\[[\"']([^\"'\]]+)[\"']\]")
_INDEX = re.compile(r"\[(?:\d+|[A-Za-z_]\w*)\]")

# The template GRAPH. A view is rarely rendered alone: it names a parent whose blocks it
# fills, and it pulls other files in. Both directions carry the SAME context by default in
# Jinja and in Django, which is why a variable a handler never mentions in the render call
# it wrote can still be read three files away.
#
# Only a name written as a string literal is followed. `{% include get_template(x) %}` is
# a view chosen at runtime and answering it would mean guessing which file (ADR-003).
_EXTENDS = re.compile(r"\{%-?\s*extends\s+(['\"])([^'\"]+)\1")
_INCLUDE = re.compile(r"\{%-?\s*include\s+(['\"])([^'\"]+)\1")

# `{% for x in items %}` binds a name to an ELEMENT of something the context supplied.
# This engine is not field-sensitive about elements -- `items[0].name` and `items[3].name`
# normalize to the same read -- so the loop variable normalizes to the sequence, which is
# what makes `{{ infobox.content }}` inside `{% for infobox in infoboxes %}` a read of
# `infoboxes.content` and connects it to the render call that passed the list.
#
# Only a simple `name in path` header. A tuple target, a filtered sequence and a call are
# each a case where the element is not the sequence.
_FOR = re.compile(r"\{%-?\s*for\s+([A-Za-z_]\w*)\s+in\s+([A-Za-z_][\w.]*)\s*-?%\}")
_FOR_ANY = re.compile(r"\{%-?\s*for\s")
_ENDFOR = re.compile(r"\{%-?\s*endfor\s*-?%\}")

# Where a `<script>` element begins and ends.
#
# A script element is not markup and is not a JavaScript string either: the HTML parser
# ends it at the first `</script` whatever the JavaScript around it says, so a value
# escaped for a JavaScript string still closes the element. Recording the context is what
# lets an encoder be judged against the place the value actually lands.
_SCRIPT_OPEN = re.compile(r"<\s*script\b", re.I)
_SCRIPT_CLOSE = re.compile(r"<\s*/\s*script\s*>", re.I)

# The contexts an interpolation can sit in, as far as this frontend is willing to say.
CONTEXT_MARKUP = "markup"
CONTEXT_SCRIPT = "script"


class Template:
    """One view, and what it writes into the page."""

    __slots__ = ("module", "reads", "extends", "includes")

    def __init__(self, module: str, reads: list[dict],
                 extends: list[str] | None = None, includes: list[str] | None = None):
        self.module = module
        self.reads = reads
        self.extends = extends or []
        self.includes = includes or []


def _position_of(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    start = source.rfind("\n", 0, offset) + 1
    return line, offset - start + 1


def _strip_markers(expr: str) -> str:
    """Whitespace-control hyphens belong to the delimiter, not to the expression."""
    return expr.strip().strip("-").strip()


def _normalize(expr: str) -> str | None:
    """The access path an interpolation reads, or None when it is not one."""
    text = _strip_markers(expr).split("|", 1)[0].strip()
    if not _PATH_ONLY.match(text) or text.lower() in _NOT_A_READ:
        return None
    # A numeric index is dropped rather than kept: this engine is not field-sensitive
    # about array elements, and `items[0].name` and `items[3].name` are the same read as
    # far as any rule here is concerned.
    return _INDEX.sub("", _SUBSCRIPT.sub(r".\1", text))


def _is_marked_safe(body: str) -> bool:
    """Whether a filter chain leaves the value unescaped.

    String arguments come out first, because `|default("|safe")` contains the filter's
    name inside a quoted default and means nothing by it. And an escaping filter appearing
    BEFORE `safe` settles it the other way: the value was escaped, and `safe` only stops it
    being escaped a second time.
    """
    return _safe_marker(body) is not None


def _safe_marker(body: str) -> int | None:
    """Where the `| safe` that turns the engine's escaping OFF is written, as an offset
    into `body`, or None when nothing removes it.

    The offset exists because an absent encoder and a REMOVED one are different facts
    about a line. Autoescaping is on, so `{{ x }}` is a decision nobody made; `{{ x|safe }}`
    is a decision somebody wrote down, and a finding that can point at the words is a
    finding a reader can act on without hunting for them. `Markup(...)` removes it too and
    has no filter to point at, which is why the answer is an offset into this body rather
    than a promise that one exists.
    """
    stripped = _strip_markers(body)
    # The leading whitespace the strip removed, so an offset is an offset into `body`.
    shift = body.find(stripped) if stripped else 0
    chain = _STRING_ARG.sub(lambda m: " " * len(m.group(0)), stripped)
    safe = _SAFE_FILTER.search(chain)
    if safe is None:
        markup = _MARKUP.search(chain)
        return None if markup is None else shift + markup.start()
    escape = _ESCAPE_FILTER.search(chain)
    if escape is not None and escape.start() < safe.start():
        return None
    return shift + safe.start()


def _blank_span(source: str, start: int, stop: int) -> str:
    """One region blanked, with newlines kept so line numbers stay true."""
    return source[:start] + re.sub(r"[^\n]", " ", source[start:stop]) + source[stop:]


def _blank(source: str) -> str:
    """Blanks out regions that are not interpolations, keeping every other character in
    place so line and column numbers stay true.

    `{% raw %}` prints its contents literally and `{# ... #}` prints nothing at all, which
    is the point of both: reporting what is inside one would be reporting a page's
    documentation of its own template language.

    Scanned linearly rather than matched with a span between two delimiters. A lazy span
    rescans from every opener, so an unclosed one repeated across a file costs one scan of
    the rest of the file each time -- and a template is the one input a scanner reads that
    an attacker may have written.
    """
    out = source
    i = 0
    while True:
        m = _RAW_OPEN.search(out, i)
        if m is None:
            break
        close = _RAW_CLOSE.search(out, m.end())
        if close is None:
            break
        out = _blank_span(out, m.start(), close.end())
        i = close.end()
    i = 0
    while True:
        start = out.find("{#", i)
        if start == -1:
            break
        end = out.find("#}", start + 2)
        if end == -1:
            break
        out = _blank_span(out, start, end + 2)
        i = end + 2
    return out


def _autoescape_off_regions(source: str) -> list[tuple[int, int]]:
    """Character ranges covered by an `{% autoescape false %}` block, which is the one
    place a bare `{{ x }}` is unescaped."""
    out = []
    for m in _AUTOESCAPE_OFF.finditer(source):
        close = source.find("endautoescape", m.start())
        out.append((m.start(), len(source) if close == -1 else close))
    return out


def _script_regions(source: str) -> list[tuple[int, int]]:
    """Character ranges INSIDE a `<script>` element.

    Scanned linearly for the same reason `_blank` is: a lazy span between two delimiters
    rescans from every opener, and a template is an input an attacker may have written.
    An unclosed `<script>` ends the scan rather than swallowing the rest of the file --
    the browser would run everything after it, but claiming a context from a tag nobody
    closed is a guess, and the quiet direction is the right one here.
    """
    out: list[tuple[int, int]] = []
    i = 0
    while True:
        m = _SCRIPT_OPEN.search(source, i)
        if m is None:
            break
        gt = source.find(">", m.end())
        if gt == -1:
            break
        close = _SCRIPT_CLOSE.search(source, gt + 1)
        if close is None:
            break
        out.append((gt + 1, close.start()))
        i = close.end()
    return out


def _loop_bindings(source: str) -> list[tuple[int, int, str, str]]:
    """Every `{% for x in items %}` block, as (start, stop, name, sequence).

    The stop is the matching `{% endfor %}`, found by counting nesting, so an inner loop
    does not close an outer one.
    """
    out: list[tuple[int, int, str, str]] = []
    # Every `for` and every `endfor` in source order; a `for` pushes and an `endfor` pops.
    # A `for` header this frontend cannot read still pushes, so that its `endfor` does not
    # close somebody else's loop -- with the name left empty, which binds nothing.
    events: list[tuple[int, int, str, str, int]] = []
    for m in _FOR_ANY.finditer(source):
        named = _FOR.match(source, m.start())
        if named is not None:
            events.append((m.start(), 0, named.group(1), named.group(2), named.end()))
        else:
            events.append((m.start(), 0, "", "", m.end()))
    events += [(m.start(), 1, "", "", m.end()) for m in _ENDFOR.finditer(source)]
    events.sort()
    stack: list[tuple[int, str, str, int]] = []
    for start, kind, name, sequence, end in events:
        if kind == 0:
            stack.append((start, name, sequence, end))
        elif stack:
            _, name, sequence, end = stack.pop()
            if name:
                out.append((end, start, name, sequence))
    # A loop nobody closed runs to the end of the file, which is what the engine does too.
    for _, name, sequence, end in stack:
        if name:
            out.append((end, len(source), name, sequence))
    return out


def _rebind(path: str, offset: int, loops: list[tuple[int, int, str, str]]) -> str:
    """The path a read denotes once the loops enclosing it are resolved.

    `{{ infobox.content }}` inside `{% for infobox in infoboxes %}` reads a field of an
    ELEMENT of `infoboxes`, and this engine is deliberately not field-sensitive about
    elements -- `items[0].name` and `items[3].name` already normalize to one read -- so the
    element normalizes to the sequence and the read becomes `infoboxes.content`. That is
    what connects an interpolation to the render call that passed the list, across the
    include boundary where the loop variable does not exist at all.

    Innermost first, and repeated, because a loop's sequence can itself be a loop
    variable: `{% for a in xs %}{% for b in a.ys %}`.
    """
    for start, stop, name, sequence in sorted(
        (l for l in loops if l[0] <= offset < l[1]), key=lambda l: -l[0]
    ):
        head, _, rest = path.partition(".")
        if head == name:
            path = sequence + ("." + rest if rest else "")
    return path


def parse_template(module: str, source: str) -> Template:
    text = _blank(source)
    off = _autoescape_off_regions(text)
    scripts = _script_regions(text)
    loops = _loop_bindings(text)
    reads = []
    for m in _INTERPOLATION.finditer(text):
        body = m.group(1)
        path = _normalize(body)
        if path is None:
            continue
        path = _rebind(path, m.start(), loops)
        in_off_block = any(a <= m.start() < b for a, b in off)
        marker = _safe_marker(body)
        escaped = not in_off_block and marker is None
        line, column = _position_of(source, m.start())
        read = {"path": path, "escaped": escaped, "line": line, "column": column}
        if any(a <= m.start() < b for a, b in scripts):
            read["context"] = CONTEXT_SCRIPT
        if marker is not None:
            # `{{` is two characters wide and the body starts after it.
            mline, mcolumn = _position_of(source, m.start() + 2 + marker)
            read["removedAt"] = {"file": module, "line": mline, "column": mcolumn}
        reads.append(read)
    # An include inherits the loops it sits inside, and that is the whole of what connects
    # `{{ infobox.content }}` in one file to `infoboxes=` in a render call in another:
    # results.html includes the element template from inside `{% for infobox in infoboxes %}`,
    # so the included file's free `infobox` is an element of the caller's `infoboxes`.
    includes = []
    for m in _INCLUDE.finditer(text):
        rebind = {
            name: sequence
            for start, stop, name, sequence in loops
            if start <= m.start() < stop
        }
        includes.append({"view": m.group(2), "rebind": rebind} if rebind else {"view": m.group(2)})
    return Template(
        module,
        reads,
        extends=[name for _, name in _EXTENDS.findall(text)],
        includes=includes,
    )


def index_templates(root: str) -> dict[str, Template]:
    """Every template under the root, by its root-relative path.

    Indexed once for the whole program rather than read at each render call: a view is
    rendered from many handlers, and reading it once is both faster and the only way a
    count of templates read means anything.
    """
    out: dict[str, Template] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRECTORIES]
        for name in filenames:
            if not name.lower().endswith(MARKUP_EXTENSIONS):
                continue
            full = os.path.join(dirpath, name)
            try:
                with open(full, encoding="utf-8", errors="replace") as fh:
                    source = fh.read()
            except OSError:
                continue
            module = os.path.relpath(full, root).replace(os.sep, "/")
            out[module] = parse_template(module, source)
    return out


def resolve_template(index: dict[str, Template], name: str, relative_to: str | None = None) -> Template | None:
    """The template a render call names.

    `relative_to` is the template doing the naming, for the half of the resolution that
    happens between two views. A loader root is some ANCESTOR directory of the file that
    names the target, which is the one thing about the search path that is true without
    reading the configuration: `share/jupyterhub/templates/home.html` extending
    `page.html` means the `page.html` beside it, not one of the two others in the tree,
    and `searx/templates/simple/results.html` including `simple/elements/infobox.html`
    means the one under its own parent. Without this, every template in a project holding
    more than one `page.html` resolved to nothing.

    Flask resolves a view name against a search path that is configuration rather than
    source, so matching on a path SUFFIX covers it without modelling that configuration:
    `render_template("index.html")` finds `templates/index.html` and
    `render_template("admin/users.html")` finds `app/templates/admin/users.html`.

    An ambiguous name -- two templates whose paths both end this way -- resolves to
    nothing. Picking one would attach a finding to a file that may not be the one
    rendered, and a finding pointing at the wrong file is worse than no finding.
    """
    # A traversal in a view name is not a view name. Jinja rejects one and so does this.
    if ".." in name:
        return None
    wanted = name.lstrip("./")
    if relative_to:
        parts = relative_to.split("/")[:-1]
        while parts:
            candidate = "/".join(parts) + "/" + wanted
            # A view that extends its own NAME is extending the one the loader finds
            # further along the search path, never itself -- an application overriding a
            # framework's `page.html` writes exactly that, and answering with the file we
            # started from would be a cycle rather than a resolution.
            if candidate in index and candidate != relative_to:
                return index[candidate]
            parts.pop()
        if wanted in index and wanted != relative_to:
            return index[wanted]
    matches = [t for p, t in index.items() if p == wanted or p.endswith("/" + wanted)]
    if len(matches) == 1:
        return matches[0]
    # A templates directory wins over a file of the same name elsewhere, because that is
    # where the loader looks: `render_template("index.html")` in a project holding both
    # `index.html` and `templates/index.html` renders the second, and answering with the
    # first would attach a finding to a file the application never renders.
    in_templates = [t for t in matches if "templates/" in t.module or t.module.startswith("templates/")]
    return in_templates[0] if len(in_templates) == 1 else None
