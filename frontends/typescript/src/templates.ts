/**
 * Line and column of an offset, 1-based, for locations a reader can click.
 *
 * The line starts are computed once per file and binary-searched. Counting newlines from
 * the beginning for every interpolation is quadratic in a large view, which is a cost
 * nobody would ever see in a fixture and everybody would see on a real template.
 */
function lineStartsOf(source: string): number[] {
  const starts = [0];
  for (let i = 0; i < source.length; i++) {
    if (source.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

function positionAt(starts: number[], offset: number): { line: number; column: number } {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: offset - starts[lo] + 1 };
}

// Template files: the half of a web application that actually writes the HTML.
//
// A view is not source in the language this frontend parses, and for most of this
// project's life that meant it was not lowered at all — which put the most common form
// of cross-site scripting outside the engine's reach. Every escaping decision a server-
// rendered application makes is made HERE, in a syntax the language's compiler has never
// heard of, and a scanner that reads only the handler reads the half where nothing is
// decided.
//
// What is extracted is deliberately small: for each interpolation, whether the engine
// escapes it, and what it reads. That is the whole of what the judgement needs. No
// attempt is made to lower control flow, partials, helpers or expressions — an
// interpolation this file cannot read is skipped, which is a stated miss rather than a
// guess (ADR-003).

import fs from "node:fs";
import path from "node:path";

/** One value written into a page. */
export interface Interpolation {
  /** The access path read, rooted at a name the render call supplies: `user.name`. */
  path: string;
  /** Whether the engine HTML-escapes this one. */
  escaped: boolean;
  /** Syntax interpreted after HTML parsing, where markup escaping is not sufficient. */
  context?: "url-target" | "url-part";
  line: number;
  column: number;
}

const URL_ATTRIBUTE = /\b(?:href|src|action)\s*=\s*(["'])(.*?)\1/gis;

function urlContextAt(source: string, offset: number): "url-target" | "url-part" | undefined {
  URL_ATTRIBUTE.lastIndex = 0;
  for (let attr = URL_ATTRIBUTE.exec(source); attr; attr = URL_ATTRIBUTE.exec(source)) {
    const valueStart = attr.index + attr[0].indexOf(attr[1]) + 1;
    const valueStop = valueStart + attr[2].length;
    if (offset < valueStart || offset >= valueStop) continue;
    const value = attr[2];
    const reads = [...value.matchAll(/<%[=-][\s\S]*?%>|\{\{\{?[\s\S]*?\}\}\}?|[!#]\{[^}]*\}/g)];
    if (reads.length !== 1) return "url-part";
    const read = reads[0];
    const before = value.slice(0, read.index).trim();
    const after = value.slice((read.index ?? 0) + read[0].length).trim();
    return before === "" && after === "" ? "url-target" : "url-part";
  }
  return undefined;
}

export interface Template {
  /** Root-relative path, used as the IR module id. */
  moduleId: string;
  engine: string;
  reads: Interpolation[];
}

export interface TemplateIndex {
  /** By root-relative path with the extension, e.g. `views/products.ejs`. */
  byPath: Map<string, Template>;
  /** Every template, for reporting how many were read. */
  all: Template[];
}

/**
 * Extensions this frontend reads, and the engine each belongs to.
 *
 * `.html` is absent from this table and handled separately. A `.html` file in a Node
 * project is as likely to be a static asset as a view, so it counts as a template only
 * where it LIVES like one — under a `views/` or `templates/` directory — which is the
 * convention every engine that renders `.html` in Node follows. Reading every `.html` in
 * a tree would invent interpolations out of anything containing braces.
 */
const ENGINES: Record<string, string> = {
  ".ejs": "ejs",
  ".hbs": "handlebars",
  ".handlebars": "handlebars",
  ".mustache": "mustache",
  ".pug": "pug",
  ".jade": "pug",
  ".njk": "nunjucks",
  ".nunjucks": "nunjucks",
  ".swig": "swig",
};

const SKIP_DIRECTORIES = new Set(["node_modules", ".git", ".yarn", "vendor", "dist", "build", "out", "coverage"]);

/** Directories whose `.html` files are views rather than assets, by universal convention. */
const VIEW_DIRECTORIES = /(^|\/)(views|templates|partials|layouts)\//;

/**
 * Which engine reads a file, or none.
 *
 * A `.html` view is read as Jinja-shaped — `{{ x }}` escaped unless a filter says
 * otherwise — because that is what swig, nunjucks and every engine in that family do, and
 * because a wrong guess in this direction under-reports rather than over-reports.
 */
function engineFor(fileName: string, moduleId: string): string | undefined {
  const ext = path.extname(fileName).toLowerCase();
  const known = ENGINES[ext];
  if (known) return known;
  if ((ext === ".html" || ext === ".htm") && VIEW_DIRECTORIES.test(moduleId)) return "swig";
  return undefined;
}

/**
 * An access path this frontend is willing to say it understands.
 *
 * `user.name`, `user["name"]`, `items[0].name` and `items[i].name` are reads of a field.
 * `helper(user)` and `a ? b : c` are not paths, and pretending they were would attach a
 * finding to a value nobody can point at. Anything that is not this shape is skipped.
 *
 * A VARIABLE index counts for the same reason a numeric one does. `<%- rows[i].name %>`
 * inside a loop is the shape every table in every application has, and refusing it meant
 * refusing the most common place an unescaped interpolation appears.
 */
const PATH_ONLY = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[["'][^"'\]]+["']\]|\[\d+\]|\[[A-Za-z_$][\w$]*\])*$/;

/** Values that are not reads of anything a render call supplied. */
const NOT_A_READ = new Set(["null", "undefined", "true", "false", "none", "this"]);

/**
 * A linear scan for delimited spans, replacing the regex that made this quadratic.
 *
 * A lazy span between two delimiters rescans from every opener, so `"{{".repeat(60000)`
 * with no closing brace costs sixty thousand scans of the rest of the file. Bounding the
 * span helps and does not fix it. Walking the string once does: find the opener, look for
 * the closer AFTER it, and continue from there — and an opener with no closer ends the
 * scan, because the rest of the file is not interpolations either.
 *
 * That property matters more here than anywhere else in this project: a template is the
 * one input a scanner reads that an attacker may have written.
 */
function scanDelimited(
  source: string,
  open: string,
  close: string,
  visit: (body: string, start: number, afterOpen: number) => void,
): void {
  let i = 0;
  for (;;) {
    const start = source.indexOf(open, i);
    if (start === -1) return;
    const bodyStart = start + open.length;
    const end = source.indexOf(close, bodyStart);
    if (end === -1) return;
    visit(source.slice(bodyStart, end), start, bodyStart);
    i = end + close.length;
  }
}

/** Whitespace-control and trim markers, which belong to the delimiter and not to the expression. */
function stripMarkers(expr: string): string {
  return expr.replace(/^[-_~]+/, "").replace(/[-_~]+$/, "").trim();
}

/**
 * The filter chain, for the engines that HAVE one.
 *
 * Only the Jinja-shaped engines use `|` as a filter separator. In EJS and Pug the same
 * character is JavaScript's bitwise or, so splitting on it there would read `x | 0` as a
 * read of `x` -- a different expression with a different value.
 */
function beforeFilter(expr: string, piped: boolean): string {
  if (!piped) return expr.trim();
  const bar = expr.indexOf("|");
  return (bar === -1 ? expr : expr.slice(0, bar)).trim();
}

function normalizePath(expr: string, piped = false): string | undefined {
  const text = beforeFilter(stripMarkers(expr), piped);
  if (!PATH_ONLY.test(text) || NOT_A_READ.has(text.toLowerCase())) return undefined;
  // `user["name"]` and `user.name` are one path, and every rule keyed on a leaf reads it
  // the second way. A numeric index is dropped rather than kept: this engine is not
  // field-sensitive about array elements, and `items[0].name` and `items[3].name` are the
  // same read as far as any rule here is concerned.
  return text
    .replace(/\[["']([^"'\]]+)["']\]/g, ".$1")
    .replace(/\[\d+\]/g, "")
    .replace(/\[[A-Za-z_$][\w$]*\]/g, "");
}

/** Line and column of an offset, 1-based, for locations a reader can click. */
function positionOf(source: string, offset: number): { line: number; column: number } {
  let line = 1;
  let lineStart = 0;
  for (let i = 0; i < offset; i++) {
    if (source.charCodeAt(i) === 10) {
      line++;
      lineStart = i + 1;
    }
  }
  return { line, column: offset - lineStart + 1 };
}

/**
 * Blanks out regions that are not interpolations at all, keeping every other character in
 * place so line and column numbers stay true.
 *
 * A raw block and a comment LOOK exactly like the syntax around them, which is the point
 * of them: `{{{{raw}}}}{{{ x }}}{{{{/raw}}}}` prints three braces and reads nothing.
 * Reporting that would be reporting a page's documentation of its own template language.
 *
 * Linear, for the same reason the interpolation scan is: a regex spanning two delimiters
 * rescans from every opener, and an unclosed one repeated across a file is the difference
 * between milliseconds and ten seconds.
 */
function blankRegions(source: string, pairs: Array<[string, string]>): string {
  let out = source;
  for (const [open, close] of pairs) {
    let i = 0;
    let built = "";
    for (;;) {
      const start = out.indexOf(open, i);
      if (start === -1) break;
      const end = out.indexOf(close, start + open.length);
      if (end === -1) break;
      const stop = end + close.length;
      built += out.slice(i, start) + out.slice(start, stop).replace(/[^\n]/g, " ");
      i = stop;
    }
    out = built + out.slice(i);
  }
  return out;
}

/**
 * A Handlebars raw block: `{{{{helper}}}} ... {{{{/helper}}}}`.
 *
 * Everything between the two tags is printed literally, braces included, which is what the
 * form is FOR. It needs its own pass because the closing tag is a tag rather than a
 * delimiter -- the opener's own `}}}}` is not the end of anything.
 */
function blankRawBlocks(source: string): string {
  let out = "";
  let i = 0;
  for (;;) {
    const open = source.indexOf("{{{{", i);
    if (open === -1 || source.startsWith("{{{{/", open)) break;
    const close = source.indexOf("{{{{/", open);
    if (close === -1) break;
    const end = source.indexOf("}}}}", close);
    if (end === -1) break;
    const stop = end + 4;
    out += source.slice(i, open) + source.slice(open, stop).replace(/[^\n]/g, " ");
    i = stop;
  }
  return out + source.slice(i);
}

type Extractor = (source: string) => Interpolation[];

/**
 * EJS. `<%= x %>` escapes, `<%- x %>` does not, and the difference is one character —
 * which is why this is the most common way an Express application gets a scripting bug.
 */
const extractEjs: Extractor = (source) => {
  const out: Interpolation[] = [];
  const starts = lineStartsOf(source);
  scanDelimited(source, "<%", "%>", (body, start) => {
    const mode = body[0];
    if (mode !== "-" && mode !== "=") return;
    const p = normalizePath(body.slice(1));
    if (!p) return;
    out.push({ path: p, escaped: mode === "=", ...positionAt(starts, start) });
  });
  return out;
};

/**
 * Handlebars and Mustache. `{{{ x }}}` and `{{& x}}` write raw HTML; `{{ x }}` escapes.
 * Block helpers (`{{#if}}`, `{{/if}}`, `{{else}}`) read nothing into the page and are
 * skipped by the path test rather than by a list of helper names, which would be wrong at
 * the first custom one.
 *
 * A `{{{{raw}}}}` block prints its contents literally, so what is inside one is text.
 */
const extractHandlebars: Extractor = (source) => {
  const out: Interpolation[] = [];
  const starts = lineStartsOf(source);
  // The block comment form first: `{{!-- ... --}}` may contain `}}` and would otherwise be
  // cut short by it. Then the raw block, whose closer is a tag of its own.
  const text = blankRawBlocks(blankRegions(source, [["{{!--", "--}}"], ["{{!", "}}"]]));
  scanDelimited(text, "{{", "}}", (body, start) => {
    // A triple brace and an ampersand both mean "do not escape". The third brace is part
    // of the body here, because the scan matched only two.
    const raw = body.startsWith("{") || body.trimStart().startsWith("&");
    const p = normalizePath(body.replace(/^\{/, "").replace(/^\s*&/, ""));
    if (!p) return;
    out.push({ path: p, escaped: !raw, ...positionAt(starts, start) });
  });
  return out;
};

/**
 * Pug. `#{x}` and `= x` escape; `!{x}` and `!= x` do not.
 *
 * A line beginning with `-` is unbuffered code that prints nothing, and a line beginning
 * with a control keyword is a statement rather than output — `while i != x` is not an
 * unescaped interpolation, however much its `!=` looks like one.
 */
const PUG_CONTROL = /^[ \t]*(-|\/\/|while\b|if\b|else\b|unless\b|each\b|for\b|case\b|when\b|mixin\b)/;

const extractPug: Extractor = (source) => {
  const out: Interpolation[] = [];
  const starts = lineStartsOf(source);
  const lines = source.split("\n");
  let offset = 0;
  for (const line of lines) {
    const lineStart = offset;
    offset += line.length + 1;
    if (PUG_CONTROL.test(line)) continue;

    const inline = /(!|#)\{([^}]{0,400})\}/g;
    for (let m = inline.exec(line); m; m = inline.exec(line)) {
      const p = normalizePath(m[2]);
      if (!p) continue;
      out.push({ path: p, escaped: m[1] === "#", ...positionAt(starts, lineStart + m.index) });
    }
    const buffered = /^[ \t]*[\w.#\-[\]="' \t]*?(!?)=[ \t]*(.+)$/.exec(line);
    if (buffered) {
      const p = normalizePath(buffered[2]);
      if (p) out.push({ path: p, escaped: buffered[1] !== "!", ...positionAt(starts, lineStart) });
    }
  }
  return out;
};

/**
 * Nunjucks, Swig and Jinja-shaped engines. Autoescaping is on, so only an explicit `|safe`
 * opts out — which makes the filter chain the whole of the judgement, and makes its ORDER
 * part of it: `x|escape|safe` was escaped before it was marked safe, and is safe.
 *
 * `{% raw %}` and `{# ... #}` are text and a comment; an `{% autoescape false %}` block
 * turns the default off for everything inside it, which is the one place a bare `{{ x }}`
 * is unescaped.
 */
const extractJinjaLike: Extractor = (source) => {
  const out: Interpolation[] = [];
  const starts = lineStartsOf(source);
  const text = blankRegions(source, [
    ["{% raw %}", "{% endraw %}"],
    ["{%- raw -%}", "{%- endraw -%}"],
    ["{#", "#}"],
  ]);
  const unescapedRegions = autoescapeOffRegions(text);
  scanDelimited(text, "{{", "}}", (body, start) => {
    const p = normalizePath(body, true);
    if (!p) return;
    const inOffBlock = unescapedRegions.some(([a, b]) => start >= a && start < b);
    out.push({
      path: p,
      escaped: !inOffBlock && !isMarkedSafe(body),
      ...positionAt(starts, start),
    });
  });
  return out;
};

/** Character ranges covered by an `{% autoescape false %}` block. */
export function autoescapeOffRegions(source: string): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  const open = /\{%-?\s*autoescape\s+(false|no|off|0)\s*-?%\}/gi;
  for (let m = open.exec(source); m; m = open.exec(source)) {
    const close = source.indexOf("endautoescape", m.index);
    out.push([m.index, close === -1 ? source.length : close]);
  }
  return out;
}

/**
 * Whether a filter chain leaves the value unescaped.
 *
 * String arguments are removed first, because `|default("|safe")` contains the filter's
 * name inside a quoted default and means nothing by it. And an escaping filter appearing
 * BEFORE `safe` settles the question the other way: the value was escaped, and `safe` only
 * stops it being escaped a second time.
 */
export function isMarkedSafe(body: string): boolean {
  const chain = stripMarkers(body).replace(/(["'])(?:\\.|(?!\1)[^\\])*\1/g, "");
  const safeAt = chain.search(/\|\s*safe\b/);
  if (safeAt === -1) return /\bMarkup\s*\(/.test(chain);
  const escapeAt = chain.search(/\|\s*(e|escape|forceescape|urlencode)\b/);
  return escapeAt === -1 || escapeAt > safeAt;
}

const EXTRACTORS: Record<string, Extractor> = {
  ejs: extractEjs,
  handlebars: extractHandlebars,
  mustache: extractHandlebars,
  pug: extractPug,
  nunjucks: extractJinjaLike,
  swig: extractJinjaLike,
};

export function parseTemplate(moduleId: string, engine: string, source: string): Template {
  const extract = EXTRACTORS[engine];
  const reads = extract ? extract(source) : [];
  const starts = lineStartsOf(source);
  for (const read of reads) {
    const offset = (starts[read.line - 1] ?? 0) + read.column - 1;
    read.context = urlContextAt(source, offset);
  }
  return { moduleId, engine, reads };
}

/**
 * Every template under the root, indexed by its root-relative path.
 *
 * Indexed once for the whole program rather than resolved from disk at each render call:
 * a view is rendered from many handlers, and reading it once is both faster and the only
 * way the count of templates read means anything.
 */
export function indexTemplates(rootDir: string): TemplateIndex {
  const byPath = new Map<string, Template>();
  const all: Template[] = [];

  const walk = (dir: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    // readdirSync returns entries in filesystem order, which differs between machines.
    // The IR is compared byte for byte against a committed golden, so the order views
    // appear in has to come from their names, the way collectSources() sorts source files.
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRECTORIES.has(entry.name)) continue;
        walk(full);
        continue;
      }
      const moduleIdEarly = path.relative(rootDir, full).split(path.sep).join("/");
      const engine = engineFor(entry.name, moduleIdEarly);
      if (!engine) continue;
      let source: string;
      try {
        source = fs.readFileSync(full, "utf8");
      } catch {
        continue;
      }
      const moduleId = moduleIdEarly;
      const t = parseTemplate(moduleId, engine, source);
      byPath.set(moduleId, t);
      all.push(t);
    }
  };

  walk(rootDir);
  return { byPath, all };
}

/**
 * The template a render call names.
 *
 * Express resolves a view name against a configured directory and a default extension,
 * neither of which is necessarily written down in the source. Matching on a path SUFFIX
 * covers both without having to model the configuration: `res.render("products")` finds
 * `views/products.ejs`, and `res.render("admin/users")` finds `views/admin/users.hbs`.
 *
 * An ambiguous name — two templates whose paths both end this way — resolves to nothing.
 * Picking one would attach a finding to a file that may not be the one rendered, and a
 * finding pointing at the wrong file is worse than no finding (ADR-003).
 */
export function resolveTemplate(index: TemplateIndex, name: string): Template | undefined {
  // A traversal in a view name is not a view name. Express rejects one and so does this.
  if (name.includes("..")) return undefined;
  const wanted = name.replace(/^\.?\//, "");

  const matches: Template[] = [];
  for (const [p, t] of index.byPath) {
    const withoutExt = p.slice(0, p.length - path.extname(p).length);
    if (withoutExt === wanted || withoutExt.endsWith(`/${wanted}`) || p.endsWith(`/${wanted}`)) {
      matches.push(t);
    }
  }
  if (matches.length === 1) return matches[0];
  // A view directory wins over a file of the same name elsewhere, because that is where
  // the framework looks: `res.render("admin")` in a project holding both `admin.ejs` and
  // `views/admin.ejs` renders the second one, and answering with the first would attach a
  // finding to a file the application never renders.
  const inViews = matches.filter((t) => VIEW_DIRECTORIES.test(t.moduleId));
  return inViews.length === 1 ? inViews[0] : undefined;
}
