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

# Flask autoescapes these and treats everything else as text. A `.txt` template is not
# markup, so an unescaped value in one is not a scripting bug -- which is why the list is
# the extensions Jinja itself autoescapes rather than every file under templates/.
MARKUP_EXTENSIONS = (".html", ".htm", ".xhtml", ".xml", ".j2", ".jinja", ".jinja2", ".njk")

SKIP_DIRECTORIES = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}

# An access path this frontend is willing to say it understands. `user.name` and
# `user["name"]` are a read of a field; `helper(user)` and `a if b else c` are not paths,
# and pretending they were would attach a finding to a value nobody can point at.
_PATH_ONLY = re.compile(r"^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*|\[[\"'][^\"'\]]+[\"']\])*$")

_INTERPOLATION = re.compile(r"\{\{(.*?)\}\}", re.S)
_SAFE_FILTER = re.compile(r"\|\s*safe\b")
_MARKUP = re.compile(r"\bMarkup\s*\(")
_SUBSCRIPT = re.compile(r"\[[\"']([^\"'\]]+)[\"']\]")


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


def _normalize(expr: str) -> str | None:
    """The access path an interpolation reads, or None when it is not one."""
    text = expr.split("|", 1)[0].strip()
    if not _PATH_ONLY.match(text):
        return None
    return _SUBSCRIPT.sub(r".\1", text)


def parse_template(module: str, source: str) -> Template:
    reads = []
    for m in _INTERPOLATION.finditer(source):
        body = m.group(1)
        path = _normalize(body)
        if path is None:
            continue
        escaped = not (_SAFE_FILTER.search(body) or _MARKUP.search(body))
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
    wanted = name.lstrip("./")
    direct = index.get(wanted)
    if direct is not None:
        return direct
    matches = [t for p, t in index.items() if p == wanted or p.endswith("/" + wanted)]
    return matches[0] if len(matches) == 1 else None
