// Workspace-package specifiers, resolved from the source tree itself.
//
// `packages/trpc/server/template-router/router.ts` imports
// `@documenso/lib/server-only/template/create-document-from-template`. That is neither a
// relative path nor an alias any tsconfig declares: it is the NAME `packages/lib`
// publishes itself under, and npm/pnpm/yarn make it resolve by symlinking the directory
// into `node_modules/@documenso/lib`. A source checkout has no `node_modules`, so the
// specifier resolves to nothing, the call lowers as `external`, and no argument reaches
// the callee's parameters.
//
// Measured on documenso at the commit in the corpus: 5,646 of its calls carried a symbol
// beginning `@documenso/`, every one of them external. That is not a documenso quirk --
// it is the layout of every workspace monorepo, so interprocedural dataflow was being cut
// at every package boundary in every one of them, silently.
//
// The mapping is discoverable without an install: every `package.json` in the tree
// declares the `name` its neighbours import it by. `tsconfig.json`'s
// `compilerOptions.paths` states the same thing explicitly and some monorepos use it
// instead -- that half is already handled in lower.ts, and this resolver is only ever
// consulted after it, so a project that declares its own mapping keeps the answer it
// declared.
//
// WHY THIS IS NOT `ts.resolveModuleName` WITH SYNTHESIZED `paths`:
// a `paths` array is tried in order and the first hit wins. This resolver has to be able
// to answer "more than one candidate, therefore none" -- a wrong edge fabricates a flow
// the program never makes, and a fabricated flow is worse than a missing one. First-hit
// ordering cannot express that refusal, so the candidate probing is done here.

import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

/**
 * Directories the frontend does not lower (index.ts `SKIP_DIRECTORIES`), plus `.git`.
 *
 * They are skipped when hunting for manifests AND when accepting a resolution: a
 * specifier answered by `dist/index.js` names a build product, which carries no body the
 * engine can follow and whose sources are in this very tree. Rejecting it lets the source
 * entry answer instead -- which is what makes medplum, whose every package points `main`
 * at an unbuilt `dist/`, resolve at all.
 */
const SKIP_DIRECTORIES = new Set(["node_modules", ".git", ".yarn", "dist", "build", "out", "coverage"]);

/** Extension precedence, the compiler's own: TypeScript before JavaScript. */
const SOURCE_EXTENSIONS = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];

const EXTENSION_OF = new Map<string, ts.Extension>([
  [".ts", ts.Extension.Ts],
  [".tsx", ts.Extension.Tsx],
  [".mts", ts.Extension.Mts],
  [".cts", ts.Extension.Cts],
  [".js", ts.Extension.Js],
  [".jsx", ts.Extension.Jsx],
  [".mjs", ts.Extension.Mjs],
  [".cjs", ts.Extension.Cjs],
]);

/** A package that ships ESM writes `./x.js` for what is `./x.ts` on disk. */
const REWRITTEN_AS_JS = new Map<string, string[]>([
  [".js", [".ts", ".tsx"]],
  [".jsx", [".tsx"]],
  [".mjs", [".mts"]],
  [".cjs", [".cts"]],
]);

/**
 * The roots a package's own files are looked for under, relative to its directory.
 *
 * `.` is documenso, whose `@documenso/lib/server-only/x` is literally
 * `packages/lib/server-only/x.ts`. `src` is medplum and reactive-resume. Both are probed
 * and the answer is only accepted when exactly ONE of them exists -- see `unique`. No
 * third convention is guessed at: each one added is another chance to answer a specifier
 * the program never meant.
 */
const PACKAGE_ROOTS = ["", "src"];

/** Condition names in the order a type-aware consumer reads them. */
const EXPORT_CONDITIONS = ["types", "typescript", "import", "module", "node", "default", "require"];

type ExportsNode = string | ExportsNode[] | { [key: string]: ExportsNode } | null;

interface Manifest {
  name?: unknown;
  main?: unknown;
  module?: unknown;
  types?: unknown;
  typings?: unknown;
  exports?: unknown;
}

interface WorkspacePackage {
  dir: string;
  manifest: Manifest;
}

/** Resolves a bare specifier to a file in this tree, or to nothing. */
export type WorkspaceResolver = (specifier: string) => ts.ResolvedModuleFull | undefined;

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

/** The first target an `exports` condition tree names, whatever format it describes. */
function conditionTarget(node: ExportsNode): string | undefined {
  if (typeof node === "string") return node;
  if (Array.isArray(node)) {
    for (const alt of node) {
      const target = conditionTarget(alt);
      if (target) return target;
    }
    return undefined;
  }
  if (!node || typeof node !== "object") return undefined;
  const table = node as { [key: string]: ExportsNode };
  for (const condition of EXPORT_CONDITIONS) {
    if (condition in table) {
      const target = conditionTarget(table[condition]);
      if (target) return target;
    }
  }
  return undefined;
}

/** `exports` as a subpath table, whichever of its three shapes it was written in. */
function exportsTable(value: unknown): Map<string, ExportsNode> | undefined {
  if (typeof value === "string") return new Map([[".", value]]);
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const entries = Object.entries(value as Record<string, ExportsNode>);
  if (entries.length === 0) return undefined;
  // A table whose keys are subpaths, versus one that is a bare condition tree for ".".
  if (entries.every(([key]) => key === "." || key.startsWith("./"))) return new Map(entries);
  return new Map<string, ExportsNode>([[".", value as ExportsNode]]);
}

/**
 * The target an `exports` table gives for one subpath.
 *
 * Node's own specificity rule: an exact key beats a pattern, and among patterns the
 * longest prefix wins. That is the package author's stated mapping, so following it is
 * not a guess even when several patterns match.
 */
function exportedTarget(table: Map<string, ExportsNode>, subpath: string): string | undefined {
  const key = subpath === "" ? "." : "./" + subpath;
  const exact = table.get(key);
  if (exact !== undefined) return conditionTarget(exact);

  let best: { prefix: string; target: string } | undefined;
  for (const [pattern, node] of table) {
    const star = pattern.indexOf("*");
    if (star === -1) continue;
    const prefix = pattern.slice(0, star);
    const suffix = pattern.slice(star + 1);
    if (!key.startsWith(prefix) || !key.endsWith(suffix)) continue;
    if (key.length < prefix.length + suffix.length) continue;
    const target = conditionTarget(node);
    if (!target || !target.includes("*")) continue;
    const filled = target.replace("*", key.slice(prefix.length, key.length - suffix.length));
    if (!best || prefix.length > best.prefix.length) best = { prefix, target: filled };
  }
  return best?.target;
}

/**
 * The targets a manifest DECLARES for a subpath, in the order a consumer reads them.
 *
 * Declared order is the ecosystem's, not this resolver's invention, so the first that
 * exists on disk answers. `types` before `main` is what TypeScript itself does; `main`
 * and `module` describe the same module in two formats. The root fields stay in the list
 * behind `exports` because a package whose `exports` names an unbuilt `dist/` has said
 * nothing usable and its `main` occasionally has.
 */
function declaredTargets(pkg: WorkspacePackage, subpath: string): string[] {
  const table = exportsTable(pkg.manifest.exports);
  const exported = table ? exportedTarget(table, subpath) : undefined;
  const roots =
    subpath === ""
      ? [pkg.manifest.types, pkg.manifest.typings, pkg.manifest.module, pkg.manifest.main]
      : [];
  return [exported, ...roots].filter((v): v is string => typeof v === "string" && v.length > 0);
}

/** Every `package.json` under the tree, keyed by the name it publishes. */
function indexPackages(rootDir: string): Map<string, WorkspacePackage | undefined> {
  const byName = new Map<string, WorkspacePackage | undefined>();

  const walk = (dir: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (SKIP_DIRECTORIES.has(entry.name)) continue;
        walk(path.join(dir, entry.name));
        continue;
      }
      if (entry.name !== "package.json") continue;
      let manifest: Manifest;
      try {
        manifest = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8")) as Manifest;
      } catch {
        continue;
      }
      const name = manifest.name;
      if (typeof name !== "string" || name === "") continue;
      // Two directories publishing one name: nothing in the tree says which the
      // specifier meant, and picking either invents a call edge. Recorded as present and
      // unresolvable, so a later manifest cannot silently win the race.
      if (byName.has(name)) {
        byName.set(name, undefined);
        continue;
      }
      byName.set(name, { dir, manifest });
    }
  };

  walk(path.resolve(rootDir));
  return byName;
}

/** `@scope/pkg/a/b` -> name `@scope/pkg`, subpath `a/b`. Relative specifiers are not ours. */
function splitSpecifier(specifier: string): { name: string; subpath: string } | undefined {
  if (specifier === "" || specifier.startsWith(".") || specifier.startsWith("#")) return undefined;
  if (specifier.startsWith("/") || path.isAbsolute(specifier)) return undefined;
  const parts = specifier.split("/");
  if (specifier.startsWith("@")) {
    if (parts.length < 2 || parts[1] === "") return undefined;
    return { name: parts.slice(0, 2).join("/"), subpath: parts.slice(2).join("/") };
  }
  if (parts[0] === "") return undefined;
  return { name: parts[0], subpath: parts.slice(1).join("/") };
}

/**
 * Resolves specifiers naming a package this tree contains.
 *
 * The index is built on the first bare specifier that nothing else could answer, so a
 * tree whose imports all resolve never pays for the walk.
 */
export function makeWorkspaceResolver(rootDir: string): WorkspaceResolver {
  const root = path.resolve(rootDir);
  let byName: Map<string, WorkspacePackage | undefined> | undefined;
  const answered = new Map<string, ts.ResolvedModuleFull | undefined>();

  /**
   * Whether a file is one the frontend would lower.
   *
   * A `.d.ts` is rejected for the same reason `dist/` is: a declaration has no body, so
   * an edge into it is not a dataflow edge, and the source it was generated from is in
   * the tree and IS followable. Only the part of the path INSIDE the tree is judged --
   * the scanner is often launched from a directory that happens to be called `build`.
   */
  const followable = (file: string): boolean => {
    if (/\.d\.[cm]?ts$/.test(file)) return false;
    if (!EXTENSION_OF.has(path.extname(file))) return false;
    const inside = path.relative(root, file);
    if (inside.startsWith("..") || path.isAbsolute(inside)) return false;
    return !inside.split(path.sep).some((segment) => SKIP_DIRECTORIES.has(segment));
  };

  /**
   * The file a candidate path names: itself, itself with an extension, or its `index`.
   *
   * Ordering WITHIN one candidate is the compiler's extension precedence and not a guess
   * -- `x.ts` and `x.js` beside each other are the same module, one compiled from the
   * other. Ordering ACROSS candidates is a guess, which is why callers use `unique`.
   */
  const probe = (base: string): string | undefined => {
    const ext = path.extname(base);
    if (EXTENSION_OF.has(ext)) {
      if (isFile(base) && followable(base)) return base;
      const stem = base.slice(0, -ext.length);
      for (const swap of REWRITTEN_AS_JS.get(ext) ?? []) {
        if (isFile(stem + swap) && followable(stem + swap)) return stem + swap;
      }
    }
    for (const e of SOURCE_EXTENSIONS) {
      if (isFile(base + e) && followable(base + e)) return base + e;
    }
    for (const e of SOURCE_EXTENSIONS) {
      const indexed = path.join(base, "index" + e);
      if (isFile(indexed) && followable(indexed)) return indexed;
    }
    return undefined;
  };

  /** The one file every candidate agrees on, or nothing when they disagree. */
  const unique = (files: Array<string | undefined>): string | undefined => {
    const hits = new Set(files.filter((f): f is string => f !== undefined));
    return hits.size === 1 ? [...hits][0] : undefined;
  };

  const resolveFile = (specifier: string): string | undefined => {
    const split = splitSpecifier(specifier);
    if (!split) return undefined;
    byName ??= indexPackages(root);
    const pkg = byName.get(split.name);
    if (!pkg) return undefined;

    // What the package says about itself comes first; the roots below are only for a
    // package that says nothing, or that points at a build it has not run.
    for (const target of declaredTargets(pkg, split.subpath)) {
      const hit = probe(path.resolve(pkg.dir, target));
      if (hit) return hit;
    }
    return unique(PACKAGE_ROOTS.map((r) => probe(path.join(pkg.dir, r, split.subpath))));
  };

  return (specifier: string): ts.ResolvedModuleFull | undefined => {
    if (answered.has(specifier)) return answered.get(specifier);
    const file = resolveFile(specifier);
    const extension = file ? EXTENSION_OF.get(path.extname(file)) : undefined;
    const resolved: ts.ResolvedModuleFull | undefined =
      file && extension ? { resolvedFileName: file, extension, isExternalLibraryImport: false } : undefined;
    answered.set(specifier, resolved);
    return resolved;
  };
}
