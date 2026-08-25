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
 * `user.name` and `user["name"]` are a read of a field. `helper(user)` and `a ? b : c`
 * are not paths, and pretending they were would attach a finding to a value nobody can
 * point at. Anything that is not this shape is skipped.
 */
const PATH_ONLY = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[["'][^"'\]]+["']\])*$/;

/** Strips template-engine filters, so `name | safe` reads as `name`. */
function beforeFilter(expr: string): string {
  const bar = expr.indexOf("|");
  return (bar === -1 ? expr : expr.slice(0, bar)).trim();
}

function normalizePath(expr: string): string | undefined {
  const text = beforeFilter(expr);
  if (!PATH_ONLY.test(text)) return undefined;
  // `user["name"]` and `user.name` are one path, and every rule keyed on a leaf reads it
  // the second way.
  return text.replace(/\[["']([^"'\]]+)["']\]/g, ".$1");
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

type Extractor = (source: string) => Interpolation[];

/**
 * EJS. `<%= x %>` escapes, `<%- x %>` does not, and the difference is one character —
 * which is why this is the most common way an Express application gets a scripting bug.
 */
const extractEjs: Extractor = (source) => {
  const out: Interpolation[] = [];
  const re = /<%(-|=)([\s\S]*?)%>/g;
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
 * skipped by the path test rather than by a list of helper names, which would be wrong
 * at the first custom one.
 */
const extractHandlebars: Extractor = (source) => {
  const out: Interpolation[] = [];
  const re = /\{\{(\{)?\s*(&)?\s*([\s\S]*?)\s*(\})?\}\}/g;
  for (let m = re.exec(source); m; m = re.exec(source)) {
    const p = normalizePath(m[3]);
    if (!p) continue;
    const raw = m[1] === "{" || m[2] === "&";
    out.push({ path: p, escaped: !raw, ...positionOf(source, m.index) });
  }
  return out;
};

/**
 * Pug. `#{x}` and `= x` escape; `!{x}` and `!= x` do not.
 */
const extractPug: Extractor = (source) => {
  const out: Interpolation[] = [];
  const inline = /(!|#)\{([\s\S]*?)\}/g;
  for (let m = inline.exec(source); m; m = inline.exec(source)) {
    const p = normalizePath(m[2]);
    if (!p) continue;
    out.push({ path: p, escaped: m[1] === "#", ...positionOf(source, m.index) });
  }
  // The tag and its attributes, then `=` or `!=`, then the expression -- all on ONE line.
  // The class deliberately excludes a newline: allowing one let the lazy part run back
  // through earlier lines and report an interpolation at the top of the file.
  const buffered = /^[ \t]*[\w.#\-[\]="' \t]*?(!?)=[ \t]*([^\n]+)$/gm;
  for (let m = buffered.exec(source); m; m = buffered.exec(source)) {
    const p = normalizePath(m[2]);
    if (!p) continue;
    out.push({ path: p, escaped: m[1] !== "!", ...positionOf(source, m.index) });
  }
  return out;
};

/**
 * Nunjucks, Swig and Jinja-shaped engines. Autoescaping is on, so only an explicit
 * `| safe` opts out — which makes the filter the whole of the judgement.
 */
const extractJinjaLike: Extractor = (source) => {
  const out: Interpolation[] = [];
  const re = /\{\{([\s\S]*?)\}\}/g;
  for (let m = re.exec(source); m; m = re.exec(source)) {
    const body = m[1];
    const p = normalizePath(body);
    if (!p) continue;
    out.push({ path: p, escaped: !isMarkedSafe(body), ...positionOf(source, m.index) });
  }
  return out;
};

/** `| safe`, `|safe`, `| e | safe` — the filter that turns escaping off. */
export function isMarkedSafe(body: string): boolean {
  return /\|\s*(safe|n)\b/.test(body) || /\bMarkup\s*\(/.test(body);
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
  const wanted = name.replace(/^\.?\//, "");
  const direct = index.byPath.get(wanted);
  if (direct) return direct;

  const matches: Template[] = [];
  for (const [p, t] of index.byPath) {
    const withoutExt = p.slice(0, p.length - path.extname(p).length);
    if (withoutExt === wanted || withoutExt.endsWith(`/${wanted}`) || p.endsWith(`/${wanted}`)) {
      matches.push(t);
    }
  }
  return matches.length === 1 ? matches[0] : undefined;
}
