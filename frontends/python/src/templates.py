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
# `user["name"]` and `items[0].name` are reads of a field; `helper(user)` and
# `a if b else c` are not paths, and pretending they were would attach a finding to a
# value nobody can point at.
_PATH_ONLY = re.compile(
    r"^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*|\[[\"'][^\"'\]]+[\"']\]|\[\d+\])*$"
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
_INDEX = re.compile(r"\[\d+\]")


class Template:
    """One view, and what it writes into the page."""

    __slots__ = ("module", "reads")

    def __init__(self, module: str, reads: list[dict]):
        self.module = module
        self.reads = reads


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
    chain = _STRING_ARG.sub("", _strip_markers(body))
    safe = _SAFE_FILTER.search(chain)
    if safe is None:
        return bool(_MARKUP.search(chain))
    escape = _ESCAPE_FILTER.search(chain)
    return escape is None or escape.start() > safe.start()


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


def parse_template(module: str, source: str) -> Template:
    text = _blank(source)
    off = _autoescape_off_regions(text)
    reads = []
    for m in _INTERPOLATION.finditer(text):
        body = m.group(1)
        path = _normalize(body)
        if path is None:
            continue
        in_off_block = any(a <= m.start() < b for a, b in off)
        escaped = not in_off_block and not _is_marked_safe(body)
        line, column = _position_of(source, m.start())
        reads.append({"path": path, "escaped": escaped, "line": line, "column": column})
    return Template(module, reads)


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


def resolve_template(index: dict[str, Template], name: str) -> Template | None:
    """The template a render call names.

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
    matches = [t for p, t in index.items() if p == wanted or p.endswith("/" + wanted)]
    if len(matches) == 1:
        return matches[0]
    # A templates directory wins over a file of the same name elsewhere, because that is
    # where the loader looks: `render_template("index.html")` in a project holding both
    # `index.html` and `templates/index.html` renders the second, and answering with the
    # first would attach a finding to a file the application never renders.
    in_templates = [t for t in matches if "templates/" in t.module or t.module.startswith("templates/")]
    return in_templates[0] if len(in_templates) == 1 else None
