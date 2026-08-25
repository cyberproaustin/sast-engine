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
  line: number;
  column: number;
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

const SKIP_DIRECTORIES = new Set(["node_modules", ".git", "dist", "build", "out", "coverage"]);

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
 * `user.name`, `user["name"]` and `items[0].name` are reads of a field. `helper(user)` and
 * `a ? b : c` are not paths, and pretending they were would attach a finding to a value
 * nobody can point at. Anything that is not this shape is skipped.
 */
const PATH_ONLY = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[["'][^"'\]]+["']\]|\[\d+\])*$/;

/** Values that are not reads of anything a render call supplied. */
const NOT_A_READ = new Set(["null", "undefined", "true", "false", "none", "this"]);

/**
 * Bounded so a pathological file cannot make the scan quadratic.
 *
 * `"{{".repeat(100000)` with no closing brace makes an unbounded lazy span rescan to the
 * end of the file from every opener. No real interpolation is anywhere near this long, so
 * the cap costs nothing and removes the shape of a denial of service in a tool people are
 * meant to run on code they did not write.
 */
const SPAN = "[\\s\\S]{0,400}?";

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
  return text.replace(/\[["']([^"'\]]+)["']\]/g, ".$1").replace(/\[\d+\]/g, "");
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
 */
function blankRegions(source: string, patterns: RegExp[]): string {
  let out = source;
  for (const re of patterns) {
    out = out.replace(re, (m) => m.replace(/[^\n]/g, " "));
  }
  return out;
}

type Extractor = (source: string) => Interpolation[];

/**
 * EJS. `<%= x %>` escapes, `<%- x %>` does not, and the difference is one character —
 * which is why this is the most common way an Express application gets a scripting bug.
 */
const extractEjs: Extractor = (source) => {
  const out: Interpolation[] = [];
  const re = new RegExp(`<%(-|=)(${SPAN})%>`, "g");
  for (let m = re.exec(source); m; m = re.exec(source)) {
    const p = normalizePath(m[2]);
    if (!p) continue;
    out.push({ path: p, escaped: m[1] === "=", ...positionOf(source, m.index) });
  }
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
  const text = blankRegions(source, [/\{\{\{\{[\s\S]*?\{\{\{\{\/[\s\S]*?\}\}\}\}/g, /\{\{!(?:--)?[\s\S]*?\}\}/g]);
  const re = new RegExp(`\\{\\{(\\{)?\\s*(&)?\\s*(${SPAN})\\s*(\\})?\\}\\}`, "g");
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const p = normalizePath(m[3]);
    if (!p) continue;
    const raw = m[1] === "{" || m[2] === "&";
    out.push({ path: p, escaped: !raw, ...positionOf(source, m.index) });
  }
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
  const lines = source.split("\n");
  let offset = 0;
  for (const line of lines) {
    const lineStart = offset;
    offset += line.length + 1;
    if (PUG_CONTROL.test(line)) continue;

    const inline = new RegExp(`(!|#)\\{(${SPAN})\\}`, "g");
    for (let m = inline.exec(line); m; m = inline.exec(line)) {
      const p = normalizePath(m[2]);
      if (!p) continue;
      out.push({ path: p, escaped: m[1] === "#", ...positionOf(source, lineStart + m.index) });
    }
    const buffered = /^[ \t]*[\w.#\-[\]="' \t]*?(!?)=[ \t]*(.+)$/.exec(line);
    if (buffered) {
      const p = normalizePath(buffered[2]);
      if (p) out.push({ path: p, escaped: buffered[1] !== "!", ...positionOf(source, lineStart) });
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
  const text = blankRegions(source, [
    /\{%-?\s*raw\s*-?%\}[\s\S]*?\{%-?\s*endraw\s*-?%\}/g,
    /\{#[\s\S]*?#\}/g,
  ]);
  const unescapedRegions = autoescapeOffRegions(text);
  const re = new RegExp(`\\{\\{(${SPAN})\\}\\}`, "g");
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const body = m[1];
    const p = normalizePath(body, true);
    if (!p) continue;
    const inOffBlock = unescapedRegions.some(([a, b]) => m.index >= a && m.index < b);
    out.push({
      path: p,
      escaped: !inOffBlock && !isMarkedSafe(body),
      ...positionOf(source, m.index),
    });
  }
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
  return { moduleId, engine, reads: extract ? extract(source) : [] };
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
