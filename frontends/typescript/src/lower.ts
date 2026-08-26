// Lowers a TypeScript program into the Program IR.
//
// This module produces IR and nothing else — it never decides whether anything is a
// vulnerability (ADR-001). It uses the TypeScript compiler's own checker as its
// semantic source (ADR-002); that is what makes cross-module call resolution real
// rather than heuristic.

import ts from "typescript";
import fs from "node:fs";
import path from "node:path";

import { IR_VERSION } from "./ir.ts";
import { indexTemplates, resolveTemplate } from "./templates.ts";
import type { TemplateIndex } from "./templates.ts";
import type {
  Arg,
  Block,
  Call,
  Callee,
  Comparison,
  Write,
  Flow,
  FunctionIR,
  IRDoc,
  Loc,
  Module,
  Param,
  Value,
  ValueKind,
} from "./ir.ts";
import { detectExpressRoutes } from "./express.ts";
import { detectDescribedRoutes, detectFileRoutes, detectHelperRoutes } from "./fileroutes.ts";
import type { ImportRef } from "./express.ts";
import {
  definedParamDecorators,
  detectNestRoutes,
  identityDecorators,
  identityParams,
  untrustedParams,
} from "./nestjs.ts";

const FRONTEND_VERSION = "0.1.0";

const COMPARISON_OPERATORS = new Set<ts.SyntaxKind>([
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
  ts.SyntaxKind.LessThanToken,
  ts.SyntaxKind.GreaterThanToken,
  ts.SyntaxKind.LessThanEqualsToken,
  ts.SyntaxKind.GreaterThanEqualsToken,
]);

// `||`, `??` and `&&` choose between their operands rather than combining them, so the
// result carries whichever was chosen and BOTH sides flow into it.
const SELECTION_OPERATORS = new Set<ts.SyntaxKind>([
  ts.SyntaxKind.BarBarToken,
  ts.SyntaxKind.QuestionQuestionToken,
  ts.SyntaxKind.AmpersandAmpersandToken,
]);

/** Values the language provides under a name, with nothing written down. */
const LANGUAGE_VALUES = new Set(["NaN", "Infinity", "undefined"]);

interface FuncMeta {
  id: string;
  name: string;
  moduleId: string;
  // The declaration this came from, so a resolver can look inside it. A factory's
  // handler is the function its body returns, and finding it means reading the body.
  node?: ts.Node;
}

/**
 * Resolves a node to the function it denotes: a function literal, or an identifier
 * bound to one (including through an import). This is what lets a callback argument
 * and a named route handler be treated the same as an inline arrow.
 */
type FunctionResolver = (node: ts.Node) => FuncMeta | undefined;

function makeFunctionResolver(
  checker: ts.TypeChecker,
  funcByNode: Map<ts.Node, FuncMeta>,
): FunctionResolver {
  // The function a factory RETURNS, when its body returns exactly one function.
  //
  // `app.post('/rest/user/login', login())` is a middleware factory, and it is how a
  // great deal of Express code is written: the handler is the RESULT of a call, so
  // resolving the call site finds `login` -- a function taking no request at all --
  // rather than the handler it produces. The route is then enumerated with a body that
  // reads nothing, no request parameter is seeded, and every defect inside the real
  // handler is invisible while the surface still looks complete. OWASP Juice Shop
  // registers its entire API this way.
  //
  // Only an unambiguous single returned function counts. A factory that returns one of
  // several functions depending on its arguments is a question this cannot answer, and
  // it says nothing rather than picking one.
  const returnedFunction = (factory: FuncMeta | undefined): FuncMeta | undefined => {
    if (!factory) return undefined;
    const decl = factory.node;
    if (!decl) return undefined;
    const body = (decl as ts.FunctionLikeDeclaration).body;
    if (!body) return undefined;

    const found: FuncMeta[] = [];
    const scan = (n: ts.Node): void => {
      if (n !== decl && isFunctionLike(n)) return;
      if (ts.isReturnStatement(n) && n.expression) {
        const inner = funcByNode.get(n.expression);
        if (inner) found.push(inner);
        return;
      }
      ts.forEachChild(n, scan);
    };
    if (ts.isBlock(body)) scan(body);
    else {
      const inner = funcByNode.get(body);
      if (inner) found.push(inner);
    }
    return found.length === 1 ? found[0] : undefined;
  };

  /**
   * Which ARGUMENT a wrapper hands the request to, when the function it returns does
   * nothing but call one of the wrapper's own parameters.
   *
   * `utils.asyncHandler(h)` returns `(req, res, next) => h(req, res, next).catch(next)`.
   * Resolving the call to the function it returns is correct and useless: the handler is
   * `h`, and the arrow is a two-line adaptor that every route in the application shares.
   * Juice Shop wraps sixty-three routes this way, and all sixty-three were enumerated as
   * one function in `lib/utils.ts` -- a surface that looked complete while pointing at
   * the same two lines over and over, and a dataflow that started nowhere near the
   * handler.
   *
   * The test is structural rather than a list of wrapper names: the returned function
   * calls a PARAMETER of the function that returned it, so the real handler is whatever
   * was passed in that position. `catchAsync`, `wrap` and `expressAsyncHandler` are the
   * same shape under other names, and a list of names would have missed the next one.
   */
  const forwardedParamIndex = (factory: FuncMeta, produced: FuncMeta): number | undefined => {
    const decl = factory.node as ts.FunctionLikeDeclaration | undefined;
    const inner = produced.node as ts.FunctionLikeDeclaration | undefined;
    if (!decl?.parameters || !inner?.body) return undefined;

    const paramIndex = new Map<ts.Symbol, number>();
    decl.parameters.forEach((param, i) => {
      if (!ts.isIdentifier(param.name)) return;
      const sym = checker.getSymbolAtLocation(param.name);
      if (sym) paramIndex.set(sym, i);
    });
    if (paramIndex.size === 0) return undefined;

    let found: number | undefined;
    let count = 0;
    const scan = (n: ts.Node): void => {
      if (ts.isCallExpression(n)) {
        const callee = ts.isPropertyAccessExpression(n.expression) ? n.expression.expression : n.expression;
        if (ts.isIdentifier(callee)) {
          const sym = checker.getSymbolAtLocation(callee);
          const at = sym ? paramIndex.get(sym) : undefined;
          if (at !== undefined) {
            count++;
            found = at;
          }
        }
      }
      ts.forEachChild(n, scan);
    };
    scan(inner.body);
    // Exactly one, for the same reason a factory returning several functions resolves to
    // none: a wrapper that calls two of its parameters is doing something this cannot
    // describe, and picking one would be a guess.
    return count === 1 ? found : undefined;
  };

  // Nodes already followed through an export table on THIS resolution, so one entry
  // naming another cannot walk in a circle.
  //
  // Per call, emphatically. A set shared across the whole program made the guard a
  // one-shot: the first `products.getProduct(...)` resolved and every later one answered
  // external, because the initializer had already been marked seen and was never followed
  // again. The cycle it guards against is within a single resolution, so that is where
  // the memory belongs.
  const resolve: FunctionResolver = (node) => resolveWith(node, new Set<ts.Node>());

  const resolveWith = (node: ts.Node, seen: Set<ts.Node>): FuncMeta | undefined => {
    const direct = funcByNode.get(node);
    if (direct) return direct;

    // A handler produced by calling a factory.
    if (ts.isCallExpression(node)) {
      const factory = resolveWith(node.expression, seen);
      const produced = returnedFunction(factory);
      if (produced && factory) {
        const at = forwardedParamIndex(factory, produced);
        const passed = at === undefined ? undefined : node.arguments[at];
        const wrapped = passed ? resolveWith(passed, seen) : undefined;
        if (wrapped) return wrapped;
      }
      if (produced) return produced;
    }

    // `sessionHandler.displayWelcomePage` and `auth.optional` are function values
    // too. Real applications register handlers and middleware this way far more
    // often than as inline literals.
    const named = ts.isPropertyAccessExpression(node) ? node.name : node;
    if (!ts.isIdentifier(named)) return undefined;

    let sym = checker.getSymbolAtLocation(named);
    if (!sym) return undefined;
    if (sym.flags & ts.SymbolFlags.Alias) {
      try {
        sym = checker.getAliasedSymbol(sym);
      } catch {
        // Unresolvable alias (module not on disk): not a local function.
      }
    }
    for (const decl of sym.declarations ?? []) {
      const viaDecl = funcByNode.get(decl);
      if (viaDecl) return viaDecl;
      if (ts.isVariableDeclaration(decl) && decl.initializer) {
        const viaInit = funcByNode.get(decl.initializer);
        if (viaInit) return viaInit;
      }
      // `module.exports.ping = function (req, res) {...}` and `exports.ping = ...`.
      // The binder makes the symbol's declaration the property access on the left of
      // the assignment, so the function is one hop away through the parent.
      //
      // Missing this shape does not lose a route — it silently moves the handler into
      // the middleware chain, because the route detector takes the last argument it
      // can RESOLVE as the handler. The route is then enumerated with no body, no
      // request parameter is ever seeded, and every defect inside it is invisible
      // while the surface still looks complete. A deliberately vulnerable application
      // with a textbook `exec('ping -c 2 ' + req.body.address)` reported clean.
      if (ts.isBinaryExpression(decl) && funcByNode.get(decl.right)) {
        return funcByNode.get(decl.right);
      }
      if (
        decl.parent &&
        ts.isBinaryExpression(decl.parent) &&
        decl.parent.left === decl &&
        funcByNode.get(decl.parent.right)
      ) {
        return funcByNode.get(decl.parent.right);
      }
      if (ts.isPropertyAssignment(decl)) {
        const inline = funcByNode.get(decl.initializer);
        if (inline) return inline;
        // `module.exports = { getProduct: getProduct, search: search }` -- the export
        // table is an object literal whose values NAME functions declared elsewhere in
        // the file, rather than holding them inline. It is the ordinary CommonJS export
        // shape and it stopped resolution dead: the call lowered as external with the
        // module path in its symbol, so a tainted argument tainted the RESULT instead of
        // entering the parameter, and every defect inside the callee went unseen. One
        // vulnerable application hid four SQL injections behind exactly this table.
        //
        // Followed one hop and no further. `{a: b}` where `b` is itself a table entry is
        // a chain nobody writes, and the guard keeps a cycle from being possible at all.
        if (ts.isIdentifier(decl.initializer) && !seen.has(decl.initializer)) {
          seen.add(decl.initializer);
          const named = resolveWith(decl.initializer, seen);
          if (named) return named;
        }
      }
    }
    return undefined;
  };
  return resolve;
}

export interface LowerOptions {
  rootDir: string;
  files: string[];
}

/** Every node_modules/@types on the path from the scanned tree up to the filesystem root. */
function typeRootsFor(rootDir: string): string[] {
  const roots: string[] = [];
  let dir = path.resolve(rootDir);
  for (;;) {
    const candidate = path.join(dir, "node_modules", "@types");
    if (fs.existsSync(candidate)) roots.push(candidate);
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return roots;
}

// --- tsconfig path aliases ------------------------------------------------
//
// `@/lib/api/controllers/links/bulk/deleteLinksById` is neither a package nor a
// relative path: it is a project's own alias, declared in its `tsconfig.json`, and `@/`
// is what every Next.js application is scaffolded with. Compiler options that do not
// carry the declaration resolve the specifier to nothing -- so the call lowers as
// external, no argument reaches the callee's parameters, and an entire controller layer
// is unreachable from the routes that call it. Two rules had already been narrowed to
// work around exactly that: one could not see linkwarden's bulk endpoints at all, and
// the other could not follow umami's `DOMAIN_REGEX` through `@/lib/constants`.
//
// The mapping belongs to a DIRECTORY rather than to a program. A monorepo has one
// tsconfig per package, `@/` means `apps/web/*` in one of linkwarden's and nothing at
// all in the next, and a single set of compiler options cannot say both. So the nearest
// config at or above a file decides how THAT file's specifiers resolve, and a package
// without a `paths` of its own gets no aliases rather than its neighbour's.
//
// The resolver is the compiler's own: `ts.resolveModuleName` given the parsed options.
// Wildcards, multi-target arrays tried in order, extension probing, `index` files, the
// `.js`-written-for-a-`.ts`-file substitution and bare non-wildcard mappings for a
// workspace package are all behaviour it already has, and a second resolver written
// here would only be a slightly different set of answers to the same question.
// `ts.parseJsonConfigFileContent` reads the config, which is what follows an `extends`
// chain and what records the base path a relative `paths` target is resolved against.

/** A tsconfig's resolution options, with the cache that answers repeat lookups. */
interface AliasProject {
  options: ts.CompilerOptions;
  cache: ts.ModuleResolutionCache;
}

/**
 * `paths` and `baseUrl` as the compiler itself reads them, including through `extends`.
 *
 * Only `compilerOptions` is wanted, so `readDirectory` answers nothing: enumerating the
 * files an `include` matches is the expensive half of parsing a config -- it globs the
 * whole subtree -- and the frontend arrives with its own list of files.
 *
 * Errors are deliberately not fatal. `"extends": "expo/tsconfig.base"` in a tree with no
 * node_modules installed is an error and the config still states its own `paths`, which
 * is the part being read.
 */
function aliasOptionsOf(configPath: string): ts.CompilerOptions | undefined {
  try {
    const read = ts.readConfigFile(configPath, (p) => ts.sys.readFile(p));
    if (!read.config) return undefined;
    const host: ts.ParseConfigHost = {
      useCaseSensitiveFileNames: ts.sys.useCaseSensitiveFileNames,
      readDirectory: () => [],
      fileExists: (p) => ts.sys.fileExists(p),
      readFile: (p) => ts.sys.readFile(p),
    };
    const parsed = ts.parseJsonConfigFileContent(
      read.config,
      host,
      path.dirname(configPath),
      undefined,
      configPath,
    );
    return parsed.options;
  } catch {
    // An unreadable or malformed config is a project that resolves as if it had none.
    return undefined;
  }
}

/**
 * A compiler host that resolves each file's specifiers under the nearest tsconfig.
 *
 * Everything else about it is the host `ts.createProgram` would have built for itself.
 */
function aliasResolvingHost(rootDir: string, base: ts.CompilerOptions): ts.CompilerHost {
  const host = ts.createCompilerHost(base);
  const root = path.resolve(rootDir);
  const canonical = (f: string): string => host.getCanonicalFileName(f);
  const fallback = ts.createModuleResolutionCache(host.getCurrentDirectory(), canonical, base);

  // Directory -> the project governing it, memoized. The walk up is done once per
  // directory and answers for every file in it; without the memo this is one stat per
  // ancestor per import in a program with hundreds of thousands of them.
  const byDirectory = new Map<string, AliasProject | undefined>();

  const projectAt = (configPath: string): AliasProject | undefined => {
    const options = aliasOptionsOf(configPath);
    // A config that declares neither is a config with nothing to add: resolution
    // proceeds on the program's own options, which is what it did before.
    if (!options?.paths && !options?.baseUrl) return undefined;
    // The project states where its own names live; everything about HOW to look is the
    // frontend's, so that one tree's `moduleResolution` cannot change what another
    // tree's files resolve to.
    const merged: ts.CompilerOptions = {
      ...base,
      baseUrl: options.baseUrl,
      paths: options.paths,
      // Set by the config parser when `paths` are declared without a `baseUrl`, and it
      // is what a relative target is resolved against. Dropping it resolves `./src/*`
      // against the process working directory, which is nowhere near the tree.
      pathsBasePath: options.pathsBasePath,
    };
    return { options: merged, cache: ts.createModuleResolutionCache(host.getCurrentDirectory(), canonical, merged) };
  };

  const projectFor = (containingFile: string): AliasProject | undefined => {
    const file = path.resolve(containingFile);
    // A declaration file out of node_modules is not part of any project in the tree,
    // and walking up from one leaves the tree entirely.
    if (!isUnder(root, file)) return undefined;

    const visited: string[] = [];
    let found: AliasProject | undefined;
    for (let dir = path.dirname(file); ; dir = path.dirname(dir)) {
      if (byDirectory.has(dir)) {
        found = byDirectory.get(dir);
        break;
      }
      visited.push(dir);
      const configPath = path.join(dir, "tsconfig.json");
      if (fs.existsSync(configPath)) {
        found = projectAt(configPath);
        break;
      }
      // Above the scanned tree as well as inside it: a tree scanned one package at a
      // time is still governed by the config that declares the package, exactly as
      // `typeRootsFor` looks upward for the @types it was installed with.
      if (path.dirname(dir) === dir) break;
    }
    for (const dir of visited) byDirectory.set(dir, found);
    return found;
  };

  host.resolveModuleNameLiterals = (literals, containingFile, redirectedReference, options, containingSourceFile) => {
    const project = projectFor(containingFile);
    const opts = project?.options ?? options;
    const cache = project?.cache ?? fallback;
    return literals.map((literal) => {
      const mode = containingSourceFile
        ? ts.getModeForUsageLocation(containingSourceFile, literal, opts)
        : undefined;
      return ts.resolveModuleName(literal.text, containingFile, opts, host, cache, redirectedReference, mode);
    });
  };

  return host;
}

export function lowerProgram(opts: LowerOptions): IRDoc {
  const compilerOptions: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Node10,
    allowJs: true,
    noEmit: true,
    skipLibCheck: true,
    // Without this, TypeScript looks for @types relative to the PROCESS working
    // directory, which is wherever the scanner happened to be launched from and
    // essentially never the tree being scanned. Every type from a dependency then
    // resolves to `any`, and the frontend answers "I don't know" to questions it could
    // have answered — which costs confidence on findings that deserved better.
    typeRoots: typeRootsFor(opts.rootDir),
  };
  const program = ts.createProgram(opts.files, compilerOptions, aliasResolvingHost(opts.rootDir, compilerOptions));
  const checker = program.getTypeChecker();
  const templates = indexTemplates(opts.rootDir);

  // Exactly the files the caller collected, and nothing resolution dragged in behind
  // them. An alias may name a build directory or a package's shipped ESM -- pdfjs maps
  // `fluent-bundle` at `./node_modules/@fluent/bundle/esm/index.js` -- and lowering one
  // reports somebody else's minified or generated code against the project that merely
  // depends on it. Resolution is for the CHECKER, which is what makes a call into such a
  // file resolve; what gets lowered stays the caller's decision.
  const collected = new Set(opts.files.map((f) => path.resolve(f)));
  const sources = program
    .getSourceFiles()
    .filter(
      (sf) =>
        !sf.isDeclarationFile &&
        isUnder(opts.rootDir, sf.fileName) &&
        collected.has(path.resolve(sf.fileName)),
    );
  indexRegexConstants(opts.rootDir, sources);

  const modules: Module[] = [];
  const funcByNode = new Map<ts.Node, FuncMeta>();
  const importsByFile = new Map<ts.SourceFile, Map<string, ImportRef>>();

  for (const sf of sources) {
    const moduleId = moduleIdOf(opts.rootDir, sf.fileName);
    modules.push({ id: moduleId, path: moduleId, isTest: isTestModule(moduleId) || undefined });
    importsByFile.set(sf, buildImportMap(sf));
    collectFunctions(sf, moduleId, funcByNode);
  }

  const resolveFunction = makeFunctionResolver(checker, funcByNode);

  // Collected across the whole program before anything is lowered: a decorator is
  // DEFINED in one file and USED in another, so a per-file pass would see every use
  // before it ever saw the definition that explains it.
  const identity = new Set<string>();
  const definedDecorators = new Set<string>();
  for (const sf of sources) {
    for (const name of identityDecorators(sf)) identity.add(name);
    for (const name of definedParamDecorators(sf)) definedDecorators.add(name);
  }

  const functions: FunctionIR[] = [];
  const entryPoints = [];

  // Group the functions by the file they live in, once.
  //
  // This loop used to scan the whole program's function map for every source file and
  // ask each entry which file it belonged to. That is quadratic, and getSourceFile()
  // walks a node's parent chain to answer, so it is quadratic with a walk inside it: on
  // one monorepo, 2,890 files times 48,575 functions came to 140 million parent-chain
  // walks and roughly nine tenths of the frontend's total runtime.
  const funcsBySource = new Map<ts.SourceFile, Array<[ts.Node, FuncMeta]>>();
  for (const [node, meta] of funcByNode) {
    const sf = node.getSourceFile();
    const bucket = funcsBySource.get(sf);
    if (bucket) bucket.push([node, meta]);
    else funcsBySource.set(sf, [[node, meta]]);
  }

  for (const sf of sources) {
    const imports = importsByFile.get(sf) ?? new Map<string, ImportRef>();
    const moduleId = moduleIdOf(opts.rootDir, sf.fileName);
    // One map per FILE, filled as each function is lowered and read by every function
    // lowered after it. That is how a name declared at the top of a file resolves inside
    // a handler halfway down, and how a callback sees what it closed over.
    const fileScope = new Map<ts.Symbol, string>();
    const fileGlobals = new Map<string, string>();
    functions.push(
      lowerFunction(
        sf,
        { id: `${moduleId}#<module>:0`, name: "<module>", moduleId },
        sf,
        checker,
        imports,
        resolveFunction,
        identity,
        templates,
        fileScope,
        fileGlobals,
      ),
    );
    for (const [node, meta] of funcsBySource.get(sf) ?? []) {
      functions.push(
        lowerFunction(node as ts.SignatureDeclaration, meta, sf, checker, imports, resolveFunction, identity, templates, fileScope, fileGlobals),
      );
    }
    // A test file's HTTP calls are not the application's attack surface. A supertest
    // client is CALLED exactly as a router is REGISTERED -- `server.post("/api/x", {...})`
    // -- and one repository contributed 1194 of its 1227 entry points that way, every one
    // a request in a test rather than a route a caller can reach.
    //
    // ADR-009 says a route that exists must appear. A route registered only in a test
    // does not exist in the program that gets deployed, which is the program this
    // enumerates.
    if (!isTestModule(moduleId)) {
      entryPoints.push(...detectExpressRoutes(sf, imports, resolveFunction, (n) => locOf(sf, n)));
      entryPoints.push(...detectNestRoutes(sf, resolveFunction, (n) => locOf(sf, n), definedDecorators));
      entryPoints.push(...detectFileRoutes(sf, moduleId, resolveFunction, (n) => locOf(sf, n)));
      entryPoints.push(...detectHelperRoutes(sf, resolveFunction, (n) => locOf(sf, n)));
      entryPoints.push(...detectDescribedRoutes(sf, resolveFunction, (n) => locOf(sf, n)));
    }
  }

  return {
    irVersion: IR_VERSION,
    frontend: {
      name: "typescript",
      version: FRONTEND_VERSION,
      capabilities: {
        typeChecker: true,
        interprocedural: true,
        crossModule: true,
        controlFlow: true,
        templates: templates.all.length > 0,
        frameworkModels: ["express", "nestjs"],
      },
    },
    modules,
    functions,
    entryPoints,
  };
}

// --- collection -----------------------------------------------------------

function isFunctionLike(node: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node)
  );
}

function collectFunctions(
  sf: ts.SourceFile,
  moduleId: string,
  out: Map<ts.Node, FuncMeta>,
): void {
  const visit = (node: ts.Node): void => {
    if (isFunctionLike(node)) {
      const name = functionNameOf(node);
      const loc = locOf(sf, node);
      // The COLUMN is part of the identity, not decoration. Two anonymous functions on
      // one line collide without it -- and `app.get("/x", (req, res) => { work(req).then(
      // (row) => res.json(row)); });` puts two on one line, which is how a great many
      // handlers are written. The entry point then names an id that resolves to the
      // callback instead of the handler: the route is enumerated, the surface looks
      // complete, and nothing inside the handler is ever reached.
      out.set(node, {
        id: `${moduleId}#${name}:${loc.line}:${loc.column}`,
        name,
        moduleId,
        node,
      });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

function functionNameOf(node: ts.Node): string {
  const named = node as ts.FunctionDeclaration;
  if (named.name && ts.isIdentifier(named.name)) return named.name.text;
  const parent = node.parent;
  if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
    return parent.name.text;
  }
  if (parent && ts.isPropertyAssignment(parent) && ts.isIdentifier(parent.name)) {
    return parent.name.text;
  }
  return "<anonymous>";
}

/** `require("x")` — the binding form most Node code still uses. */
/**
 * `node:fs` and `fs` are the same module spelled two ways.
 *
 * The symbol a channel is described against has to be the module's identity, not one
 * of its spellings — otherwise a codebase using the prefixed form has invisible sinks
 * and reports clean. Normalizing here keeps the model free of spelling variants.
 */
/**
 * Where the runtime's own type declarations live.
 *
 * This is a fact about the language, which is the frontend's side of the seam — not a
 * list of things that are not databases, which would be a security rule in the wrong
 * place. Nothing the Node runtime provides is a store of records shared between
 * callers.
 */
const RUNTIME_TYPES = /node_modules\/@types\/node\//;

/** The value of an argument written as a literal, for defects visible in the call. */
function literalOf(node: ts.Expression): string | undefined {
  if (ts.isStringLiteralLike(node)) return node.text;
  if (ts.isNumericLiteral(node)) return node.text;
  if (node.kind === ts.SyntaxKind.TrueKeyword) return "true";
  if (node.kind === ts.SyntaxKind.FalseKeyword) return "false";
  if (node.kind === ts.SyntaxKind.NullKeyword) return "null";
  return undefined;
}

/**
 * Every module-scope `const NAME = /pattern/` in the tree, by name.
 *
 * The checker resolves an imported name to the constant it came from only when it can
 * resolve the module, and a project that writes `@/lib/constants` has told tsconfig what
 * `@` means -- which is not something the compiler options built here say. Rather than
 * teach the frontend a project's path aliases, the table answers the narrower question
 * directly: which module-scope regular-expression constant does this imported name refer
 * to? An answer is given only when exactly one candidate matches both the name and the
 * tail of the import specifier, so two `PATTERN` constants in two files stay two.
 *
 * Filled once per program, before anything is lowered.
 */
type RegexConstant = { module: string; text: string };
const regexConstants = new Map<string, RegexConstant[]>();

function indexRegexConstants(rootDir: string, sources: readonly ts.SourceFile[]): void {
  regexConstants.clear();
  for (const sf of sources) {
    const moduleId = moduleIdOf(rootDir, sf.fileName);
    for (const stmt of sf.statements) {
      if (!ts.isVariableStatement(stmt)) continue;
      if (!(stmt.declarationList.flags & ts.NodeFlags.Const)) continue;
      for (const decl of stmt.declarationList.declarations) {
        if (!ts.isIdentifier(decl.name) || !decl.initializer) continue;
        if (!ts.isRegularExpressionLiteral(decl.initializer)) continue;
        const list = regexConstants.get(decl.name.text) ?? [];
        list.push({ module: moduleId, text: decl.initializer.text });
        regexConstants.set(decl.name.text, list);
      }
    }
  }
}

/** Strips a path alias or a relative prefix: `@/lib/constants` and `../constants`. */
function bareModulePath(spec: string): string {
  let out = spec;
  for (;;) {
    const next = out.replace(/^(\.\.\/|\.\/|[@~#]\/)/, "");
    if (next === out) return next;
    out = next;
  }
}

function moduleTailMatches(moduleId: string, wanted: string): boolean {
  const bare = moduleId.replace(/\.[cm]?[jt]sx?$/, "").replace(/\/index$/, "");
  return bare === wanted || bare.endsWith(`/${wanted}`);
}

function importedRegexConstant(name: string, imported: ImportRef | undefined): string | undefined {
  if (!imported || imported.export === "*") return undefined;
  const candidates = regexConstants.get(name);
  if (!candidates) return undefined;
  const wanted = bareModulePath(imported.module);
  const matches = candidates.filter((c) => moduleTailMatches(c.module, wanted));
  return matches.length === 1 ? matches[0].text : undefined;
}

/** JavaScript and TypeScript test-file conventions. */
const TEST_PATH = /(^|\/)(__tests__|__mocks__|tests?|spec|e2e|__e2e__)\/|\.(test|spec|e2e)\.[cm]?[jt]sx?$|(^|\/)(jest|vitest|playwright|cypress)\.(config|setup)\./;

function isTestModule(moduleId: string): boolean {
  return TEST_PATH.test(moduleId);
}

function normalizeModule(name: string): string {
  return name.startsWith("node:") ? name.slice("node:".length) : name;
}

function requiredModule(expr: ts.Expression | undefined): string | undefined {
  if (!expr || !ts.isCallExpression(expr)) return undefined;
  if (!ts.isIdentifier(expr.expression) || expr.expression.text !== "require") return undefined;
  const arg = expr.arguments[0];
  return arg && ts.isStringLiteralLike(arg) ? normalizeModule(arg.text) : undefined;
}

function buildImportMap(sf: ts.SourceFile): Map<string, ImportRef> {
  const map = new Map<string, ImportRef>();

  // CommonJS. Reading only ESM imports left the frontend blind to most real Node
  // applications: with no binding for "express", no route is ever recognized.
  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      // const express = require("express")
      const direct = requiredModule(node.initializer);
      if (direct && ts.isIdentifier(node.name)) {
        map.set(node.name.text, { module: direct, export: "default" });
      }
      // const { Router } = require("express")
      if (direct && ts.isObjectBindingPattern(node.name)) {
        for (const element of node.name.elements) {
          if (!ts.isIdentifier(element.name)) continue;
          const key = element.propertyName ?? element.name;
          if (ts.isIdentifier(key)) {
            map.set(element.name.text, { module: direct, export: key.text });
          }
        }
      }
      // const router = require("express").Router
      if (ts.isPropertyAccessExpression(node.initializer) && ts.isIdentifier(node.name)) {
        const viaProp = requiredModule(node.initializer.expression);
        if (viaProp) {
          map.set(node.name.text, { module: viaProp, export: node.initializer.name.text });
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  for (const stmt of sf.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
    const moduleName = normalizeModule(stmt.moduleSpecifier.text);
    const clause = stmt.importClause;
    if (!clause) continue;

    if (clause.name) {
      map.set(clause.name.text, { module: moduleName, export: "default" });
    }
    const bindings = clause.namedBindings;
    if (!bindings) continue;

    if (ts.isNamespaceImport(bindings)) {
      map.set(bindings.name.text, { module: moduleName, export: "*" });
    } else {
      for (const el of bindings.elements) {
        map.set(el.name.text, {
          module: moduleName,
          export: (el.propertyName ?? el.name).text,
        });
      }
    }
  }
  return map;
}

// --- per-function lowering ------------------------------------------------

function lowerFunction(
  node: ts.SignatureDeclaration | ts.SourceFile,
  meta: FuncMeta,
  sf: ts.SourceFile,
  checker: ts.TypeChecker,
  imports: Map<string, ImportRef>,
  resolveFunction: FunctionResolver,
  identity: Set<string>,
  // Every template under the root, read once for the whole program.
  templates: TemplateIndex,
  // Every name bound anywhere in this file, shared across all of its functions.
  //
  // Two gaps in one table. `const IV = randomBytes(16)` above a handler and `IV` inside
  // it are the same value; so are `const query = ...` in a route and the `query` a
  // `.then()` callback closes over three lines later. Without the link the second is an
  // identifier that resolves to nothing, which lost a client, a key, a cache, and every
  // value a callback captured rather than received.
  //
  // Keyed by SYMBOL, so two different `query` bindings in one file are two entries and
  // never confused: a symbol is a declaration, not a name. Functions are lowered
  // outermost first, which is what makes an outer binding present by the time the
  // callback that captures it is lowered.
  fileScope: Map<ts.Symbol, string>,
  // Names assigned without ever being declared, keyed by NAME because there is no symbol
  // to key them by -- that is what makes them implicit globals in the first place.
  fileGlobals: Map<string, string>,
): FunctionIR {
  const values: Value[] = [];
  const flows: Flow[] = [];
  const calls: Call[] = [];
  const comparisons: Comparison[] = [];
  const writes: Write[] = [];
  const blocks: Block[] = [];
  const returns: string[] = [];
  const params: Param[] = [];
  const bySymbol = new Map<ts.Symbol, string>();
  // Object-literal value id -> the value behind each of its keys. Only object literals
  // have one; anything built elsewhere is a value with no readable fields, which is what
  // makes a render call whose locals came from another function a stated miss.
  const objectFields = new Map<string, Map<string, string>>();
  const propCache = new Map<string, string>();

  let valueCount = 0;
  let callCount = 0;
  let blockCount = 0;

  const newBlock = (node: ts.Node): string => {
    const id = `${meta.id}$b${blockCount++}`;
    blocks.push({ id, successors: [], loc: locOf(sf, node) });
    return id;
  };
  const blockAt = (id: string): Block | undefined => blocks.find((b) => b.id === id);
  const link = (from: string, to: string): void => {
    const b = blockAt(from);
    if (b && !b.successors!.includes(to)) b.successors!.push(to);
  };
  const terminate = (id: string, kind: string): void => {
    const b = blockAt(id);
    if (b) b.terminator = kind;
  };
  const leaves = (id: string): boolean => {
    const t = blockAt(id)?.terminator;
    return t === "return" || t === "throw";
  };

  const entryBlock = newBlock(node);
  let current = entryBlock;

  const newValue = (kind: ValueKind, loc: Loc, extra: Partial<Value> = {}): string => {
    const id = `${meta.id}$v${valueCount++}`;
    values.push({ id, kind, loc, ...extra });
    return id;
  };

  /**
   * The receiver's type, and whether that type comes from the language itself.
   *
   * "builtin" means the standard library — Map, Set, Array, Promise. Nothing there is
   * a store of records shared between callers, so no question about who owns a record
   * can arise for it. Read from the checker rather than from a list of names, so it
   * stays correct as the language grows. Returning nothing is the honest answer for an
   * unresolvable receiver and must never be read as "not builtin".
   */
  const receiverTypeOf = (node: ts.Expression): { type?: string; origin?: string } => {
    let type: ts.Type;
    try {
      type = checker.getTypeAtLocation(node);
    } catch {
      return {};
    }
    const symbol = type.getSymbol() ?? type.aliasSymbol;
    if (!symbol) return {};

    for (const decl of symbol.declarations ?? []) {
      const file = decl.getSourceFile().fileName;
      // Two things count as the language rather than the application: the lib.*.d.ts
      // files (hasNoDefaultLib marks exactly those, so this needs the checker only and
      // no reference to the Program, which does not reach here), and the runtime's own
      // type declarations. `Hash` and `Hmac` are as much part of the language as `Map`
      // is — `hmac.update(data)` is a name collision with a record update, and there is
      // no store behind it whose records anyone could own.
      if (decl.getSourceFile().hasNoDefaultLib || RUNTIME_TYPES.test(file)) {
        return { type: symbol.getName(), origin: "builtin" };
      }
    }

    // A MODULE is not a thing with records in it. `sdk.navigation.update(id, body)`
    // calls a function out of an imported module, and `order.update(...)` operates on
    // an object; the two are the same syntax and nothing else in common. The checker
    // types a namespace import as the module's own path, which is how they are told
    // apart -- and without telling them apart, budibase's entire SDK layer read as a
    // store of shared records and asked who owned each of them.
    if (symbol.flags & (ts.SymbolFlags.ValueModule | ts.SymbolFlags.NamespaceModule)) {
      return { type: symbol.getName(), origin: "module" };
    }
    return { type: symbol.getName() };
  };

  // Statements the block builder does not model: a loop, whose back edge is never
  // emitted, and a `switch`, whose arms are lowered as if they all ran. Inside one of
  // these, `current` names a block that claims an edge is unavoidable when it is not,
  // and the reaching-definition analysis in the core would read that claim as licence to
  // kill an earlier definition. So the frontend declines to state a position at all.
  //
  // The bias is deliberate and it only goes one way: a flow with no block is kept by the
  // core, a flow with a wrong block could be dropped, and a dropped flow is a missed
  // weakness (ADR-003).
  let unmodelled = 0;

  const addFlow = (from: string | undefined, to: string, kind: Flow["kind"], loc: Loc): void => {
    if (from && to) flows.push({ from, to, kind, loc, block: unmodelled === 0 ? current : undefined });
  };

  // Where a write sits in the block graph, on the same terms as a flow: a loop body and
  // a switch arm are positions the graph does not express, so the frontend states none.
  const writeBlock = (): string | undefined => (unmodelled === 0 ? current : undefined);

  const bind = (name: ts.Identifier, valueId: string): void => {
    const sym = checker.getSymbolAtLocation(name);
    if (!sym) return;
    bySymbol.set(sym, valueId);
    // Also into the file's shared table, which is what makes a CLOSURE see what it
    // captured. Functions are lowered outermost first, so by the time a callback is
    // lowered the names it closes over are already there.
    fileScope.set(sym, valueId);
  };

  // Whether a name was declared outside the function being lowered. `let current` at a
  // module's top level assigned inside a handler is process-wide state; the identical
  // statement on a name declared in the handler is a local and means nothing.
  //
  // Imports and function declarations are excluded: rebinding one is a different mistake
  // and not this one.
  /** A name with no declaration anywhere: an implicit global. */
  const undeclaredName = (name: ts.Identifier): boolean => {
    const sym = checker.getSymbolAtLocation(name);
    if (!sym) return true;
    if (bySymbol.has(sym) || fileScope.has(sym)) return false;
    return (sym.declarations ?? []).length === 0;
  };

  const declaredOutside = (name: ts.Identifier): boolean => {
    const sym = checker.getSymbolAtLocation(name);
    const decls = sym?.declarations ?? [];
    if (decls.length === 0) return false;
    for (const decl of decls) {
      if (!ts.isVariableDeclaration(decl)) return false;
      if (decl.getSourceFile() !== sf) return false;
      for (let p: ts.Node | undefined = decl; p; p = p.parent) {
        if (p === node) return false;
        if (ts.isSourceFile(p)) break;
      }
    }
    return true;
  };

  // A module has no parameters and no decorators on them. Asking either question of a
  // source file reaches into a property that is not there.
  const injected = ts.isSourceFile(node) ? new Set<number>() : untrustedParams(node);
  const identityInjected = ts.isSourceFile(node)
    ? new Set<number>()
    : identityParams(node, identity);

  // `@Param('id') id: string` carries caller-supplied data directly; there is no request
  // object to take a property of, so the parameter itself is the origin. Identity wins
  // over untrusted when a parameter somehow carries both markers: misreading the caller's
  // identity as caller-supplied data would let the engine satisfy an ownership check with
  // the very value being checked.
  const paramKind = (index: number): ValueKind =>
    identityInjected.has(index)
      ? "actor-identity-param"
      : injected.has(index)
        ? "untrusted-param"
        : "param";
  const parameters = ts.isSourceFile(node) ? [] : node.parameters;
  parameters.forEach((p, index) => {
    const loc = locOf(sf, p);

    // A destructured parameter is still a parameter. `@AuthWorkspace() { id: workspaceId }`
    // was skipped entirely by the identifier check below, so the binding got no value at
    // all and the decorator's classification was lost with it: the handler read as having
    // never been given the caller's identity, and every query it scoped by that identity
    // read as unscoped. One production codebase writes it this way 142 times out of 462.
    //
    // Each bound name inherits the parameter's classification, because destructuring
    // chooses which part of the value to name, not what the value is.
    if (!ts.isIdentifier(p.name)) {
      if (!ts.isObjectBindingPattern(p.name) && !ts.isArrayBindingPattern(p.name)) return;
      const kind = paramKind(index);
      for (const bound of bindingPaths(p.name)) {
        const id = newValue(kind, loc, { name: bound.name.text, path: bound.path.join(".") });
        bind(bound.name, id);
      }
      return;
    }

    const id = newValue(paramKind(index), loc, { name: p.name.text });
    bind(p.name, id);
    params.push({ index, name: p.name.text, valueId: id });
  });

  const localTarget = (name: ts.Node): string | undefined => resolveFunction(name)?.id;

  // A name the RUNTIME provides rather than the application: `eval` and `Function` come
  // from the language's own lib files, and `require` comes from the Node type
  // declarations. Both are globals nobody imported and neither is a local function.
  //
  // Only lib.*.d.ts counted before, so a bare `require(...)` lowered as unresolved with
  // no symbol at all -- and a channel described against `require` matched nothing,
  // however plainly the caller chose the module.
  const isLibDeclared = (name: ts.Node): boolean => {
    const sym = checker.getSymbolAtLocation(name);
    for (const decl of sym?.declarations ?? []) {
      const file = decl.getSourceFile().fileName;
      if (file.includes("/lib.") && file.endsWith(".d.ts")) return true;
      if (RUNTIME_TYPES.test(file)) return true;
    }
    return false;
  };

  /**
   * The value of an argument written as a CONST somewhere above the call.
   *
   * `const ALGO = "md5"; crypto.createHash(ALGO)` names the algorithm exactly as plainly
   * as writing it at the call, and every rule that reads a written argument saw nothing.
   * Naming a constant is what a codebase does when the same value is used twice.
   *
   * `const` only. A `let` can be reassigned, and a rule that reads the initializer of a
   * name the program is free to change is reading something that may not be there when
   * the call runs.
   */
  const constantOf = (node: ts.Expression): string | undefined => {
    if (!ts.isIdentifier(node)) return undefined;
    const sym = checker.getSymbolAtLocation(node);
    for (const decl of sym?.declarations ?? []) {
      if (!ts.isVariableDeclaration(decl) || !decl.initializer) continue;
      const list = decl.parent;
      if (!ts.isVariableDeclarationList(list) || !(list.flags & ts.NodeFlags.Const)) continue;
      return literalOf(decl.initializer);
    }
    return undefined;
  };

  /**
   * The text of a regular expression, whether it was written at the call or bound to a
   * name somewhere else -- including in another module, which is where a shared pattern
   * lives.
   *
   * `literalOf` deliberately reads only values a program HOLDS. A pattern is not one: it
   * is a description of values a program will recognise, and it is left out of the literal
   * vocabulary so that a rule looking for a written-down secret never reads a scanner's
   * own detector as one. But a rule about the pattern itself needs the text, and
   * `z.string().regex(DOMAIN_REGEX)` -- a schema field validated by an imported constant --
   * is how request validation is actually written. Recorded as the argument's literal so
   * the core can read it without following anything.
   */
  const regexTextOf = (node: ts.Expression): string | undefined => {
    if (ts.isRegularExpressionLiteral(node)) return node.text;
    if (!ts.isIdentifier(node)) return undefined;
    let sym = checker.getSymbolAtLocation(node);
    // An imported name resolves to the IMPORT, whose declaration is the specifier rather
    // than the constant. A shared pattern is always imported -- umami's lives in
    // `constants.ts` and is used from a route -- so stopping at the alias would mean this
    // only ever read a pattern written in the same file it is used in.
    if (sym && sym.flags & ts.SymbolFlags.Alias) {
      try {
        sym = checker.getAliasedSymbol(sym);
      } catch {
        sym = undefined;
      }
    }
    for (const decl of sym?.declarations ?? []) {
      if (!ts.isVariableDeclaration(decl) || !decl.initializer) continue;
      const list = decl.parent;
      if (!ts.isVariableDeclarationList(list) || !(list.flags & ts.NodeFlags.Const)) continue;
      if (ts.isRegularExpressionLiteral(decl.initializer)) return decl.initializer.text;
    }
    return importedRegexConstant(node.text, imports.get(node.text));
  };

  /** Whether the checker says a call's signature returns `never`. */
  const returnsNever = (call: ts.CallExpression): boolean => {
    const signature = checker.getResolvedSignature(call);
    if (!signature) return false;
    return (checker.getReturnTypeOfSignature(signature).flags & ts.TypeFlags.Never) !== 0;
  };

  const resolveCallee = (call: ts.CallExpression | ts.NewExpression): Callee => {
    const expr = call.expression;
    // What it was WRITTEN as, whatever it resolves to. An unresolved call used to carry
    // no identity at all, so no rule could say anything about one -- and `next(err)` in
    // an Express handler resolves to nothing, because `next` is a parameter.
    const written = ts.isIdentifier(expr)
      ? expr.text
      : ts.isPropertyAccessExpression(expr)
        ? expr.name.text
        : undefined;
    const named = (c: Callee): Callee => (written ? { ...c, name: written } : c);

    if (ts.isIdentifier(expr)) {
      const local = localTarget(expr);
      if (local) return named({ kind: "local", functionId: local, resolution: "resolved" });

      const imported = imports.get(expr.text);
      if (imported && imported.export !== "*") {
        return named({
          kind: "external",
          symbol: `${imported.module}.${imported.export}`,
          resolution: "resolved",
        });
      }
      if (isLibDeclared(expr)) {
        return named({ kind: "external", symbol: expr.text, resolution: "resolved" });
      }
      // `require` is CommonJS's own, and a project without @types/node on the path gives
      // the checker nothing to resolve it against -- which is most fixtures and plenty of
      // real repositories. A local binding of that name was already returned above, so
      // reaching here means the global.
      if (expr.text === "require") {
        return named({ kind: "external", symbol: "require", resolution: "resolved" });
      }
      return named({ kind: "unresolved", resolution: "dynamic-unresolved" });
    }

    if (ts.isPropertyAccessExpression(expr)) {
      const root = expr.expression;
      // Asked BEFORE the import map, and the order is load-bearing. A CommonJS
      // `require("../model/products")` puts the module in the import map, so
      // `db_products.getProduct(id)` answered with the module path and stopped there --
      // even though the function is in this very tree and was lowered minutes ago. The
      // argument then tainted the call's RESULT instead of the callee's parameter, and
      // four SQL injections behind that export table were invisible.
      //
      // Safe to ask first because this only ever answers with a function the frontend
      // itself lowered from the scanned sources. A library function is not in that map,
      // so `import serialize from "node-serialize"` still falls through to the import
      // branch below and still resolves to `node-serialize.unserialize`.
      const inTree = localTarget(expr.name);
      if (inTree) return named({ kind: "local", functionId: inTree, resolution: "resolved" });
      if (ts.isIdentifier(root)) {
        const imported = imports.get(root.text);
        // A namespace import and a default import both name a module, and a property
        // taken off either belongs to that module. Qualifying only the namespace form
        // left `import serialize from "node-serialize"` resolving to
        // `serialize.unserialize` -- the local binding rather than the library -- so a
        // channel described against the module matched nothing.
        //
        // It went unnoticed because the conventional binding name usually equals the
        // module name: `import axios from "axios"` produces `axios.get` either way, and
        // only agrees by coincidence. `import ax from "axios"` did not.
        if (imported && (imported.export === "*" || imported.export === "default")) {
          return named({
            kind: "external",
            symbol: `${imported.module}.${expr.name.text}`,
            resolution: "resolved",
          });
        }
      }
      const symbol = `${root.getText(sf)}.${expr.name.text}`;
      return named({
        kind: "external",
        symbol,
        resolution: isLibDeclared(expr.name) ? "resolved" : "probable",
      });
    }

    return named({ kind: "unresolved", resolution: "dynamic-unresolved" });
  };

  // `req.auth?.user!.id` is one property chain, but the non-null assertion is a
  // different node kind sitting in the middle of it. Walking only property accesses
  // truncates the chain, and the value silently loses its path — which turns a real
  // ownership guard into a missed one.
  const unwrap = (e: ts.Expression): ts.Expression => {
    let cur = e;
    while (ts.isNonNullExpression(cur) || ts.isParenthesizedExpression(cur)) {
      cur = cur.expression;
    }
    return cur;
  };

  // The value standing for a global, one per name per function.
  const globals = new Map<string, string>();
  const globalBase = (name: ts.Identifier): string | undefined => {
    if (imports.has(name.text)) return undefined;
    if (resolveFunction(name)) return undefined;
    const cached = globals.get(name.text);
    if (cached) return cached;
    const id = newValue("global", locOf(sf, name), { name: name.text });
    globals.set(name.text, id);
    return id;
  };

  const lowerProperty = (node2: ts.PropertyAccessExpression): string | undefined => {
    const segments: string[] = [];
    let cur: ts.Expression = node2;
    for (;;) {
      cur = unwrap(cur);
      if (!ts.isPropertyAccessExpression(cur)) break;
      segments.unshift(cur.name.text);
      cur = cur.expression;
    }
    let baseId: string | undefined;
    if (ts.isIdentifier(cur)) {
      const sym = checker.getSymbolAtLocation(cur);
      baseId = sym ? bySymbol.get(sym) ?? fileScope.get(sym) : undefined;
      if (!baseId) {
        // A name with no local binding and no import is a GLOBAL, and some globals hold
        // things worth tracking: `process.env` is where a process keeps every secret it
        // was started with. Created only as the base of a property access, because that
        // is the only shape a rule describes a global in -- lowering every unresolved
        // identifier would fill the IR with `console` and `JSON` for nothing.
        baseId = globalBase(cur);
      }
    } else {
      // A chain that does not bottom out at a NAME. `url.parse(req.url, true).query` is
      // the shape that made this worth fixing: the base is a call, the walk stopped, and
      // the whole read was dropped -- along with the request it started from. The same
      // applies to `JSON.parse(body).id` and `rows[0].email`, which is most of how real
      // code gets at the value it is about to use.
      baseId = lowerExpr(cur);
    }
    if (!baseId) return undefined;

    const dotted = segments.join(".");
    const key = `${baseId}|${dotted}`;
    const cached = propCache.get(key);
    if (cached) return cached;

    const loc = locOf(sf, node2);
    const id = newValue("property", loc, { base: baseId, path: dotted, name: dotted });
    addFlow(baseId, id, "property", loc);
    propCache.set(key, id);
    return id;
  };

  /**
   * Where a render call ends and a view begins.
   *
   * `res.render("products", { query })` hands a set of named values to a file this
   * frontend has already read, and that file decides which of them are escaped. The two
   * halves are joined HERE rather than by making the template a function the call
   * targets: a view's parameters are its variable names rather than positions, and the
   * mapping from a render call's object literal to those names is the whole of the link.
   *
   * The interpolation becomes a call at the TEMPLATE's location, so a finding points at
   * the line that writes the page rather than at the handler that asked for it. Both
   * escaped and unescaped reads are recorded: escaping settles cross-site scripting and
   * settles nothing about a password rendered into a page.
   *
   * Silent, by design, when the view name is not written in the call, when two templates
   * could answer to it, or when the locals were built somewhere else -- each is a case
   * where naming a file would mean guessing which one (ADR-003).
   */
  const lowerRenderedTemplate = (expr: ts.CallExpression, args: Arg[]): void => {
    const name = expr.arguments[0];
    if (!name || !ts.isStringLiteralLike(name)) return;
    const view = resolveTemplate(templates, name.text);
    if (!view || view.reads.length === 0) return;

    const localsId = args.find((a) => a.index === 1)?.valueId;
    const fields = localsId ? objectFields.get(localsId) : undefined;
    if (!fields) return;

    for (const read of view.reads) {
      const root = read.path.split(".")[0];
      const from = fields.get(root);
      if (!from) continue;
      const at: Loc = { file: view.moduleId, line: read.line, column: read.column };
      // The path BELOW the root is a read out of the value the handler passed, and the
      // rules that ask what a field is called read it exactly this way.
      let valueId = from;
      const rest = read.path.slice(root.length + 1);
      if (rest) {
        valueId = newValue("property", at, { base: from, path: rest, name: rest });
        addFlow(from, valueId, "property", at);
      }
      const symbol = read.escaped ? "<template>.escaped" : "<template>.unescaped";
      calls.push({
        id: `${meta.id}$c${callCount++}`,
        loc: at,
        callee: { kind: "external", symbol, resolution: "resolved" },
        args: [{ index: 0, valueId }],
        argCount: 1,
        resultValueId: newValue("call-result", at, { name: symbol }),
        block: current,
      });
    }
  };

  const lowerExpr = (expr: ts.Expression): string | undefined => {
    if (ts.isParenthesizedExpression(expr)) return lowerExpr(expr.expression);
    if (ts.isAwaitExpression(expr)) return lowerExpr(expr.expression);
    if (ts.isNonNullExpression(expr)) return lowerExpr(expr.expression);
    if (ts.isAsExpression(expr)) return lowerExpr(expr.expression);
    // `x satisfies T` is a type assertion like `as`, and was falling through -- so a
    // value passed through one stopped being related to anything.
    if (ts.isSatisfiesExpression(expr)) return lowerExpr(expr.expression);
    // A TAGGED template is deliberately NOT unwrapped to its text. The tag is a
    // function and in practice it is the one that makes the thing safe: `sql`SELECT ...
    // ${id}`` in postgres.js parameterises, and `html`<p>${x}</p>`` in lit escapes.
    // Lowering it as the raw composition would report the two most common ways of
    // writing this correctly as though they were concatenation. Saying nothing is the
    // pre-existing behaviour and it is the right one until the tag itself is modelled.

    if (ts.isIdentifier(expr)) {
      const sym = checker.getSymbolAtLocation(expr);
      const bound = sym ? bySymbol.get(sym) ?? fileScope.get(sym) : undefined;
      // An implicit global has no symbol to be keyed by, which is exactly why it needs
      // the name-keyed table: `output = {...}` in one function and `output` in another
      // are the same variable and the checker has nothing to say about it.
      if (bound) return bound;
      const global = fileGlobals.get(expr.text);
      if (global) return global;
      // A name the LANGUAGE provides. `NaN`, `Infinity` and `undefined` are values with
      // nothing written down and nothing to bind to, so they lowered to nothing at all --
      // and a rule that wants to say `x === NaN` is a branch that never runs had no value
      // to point at. `session.user_id = undefined` was invisible for the same reason.
      if (LANGUAGE_VALUES.has(expr.text)) {
        return newValue("local", locOf(sf, expr), { name: expr.text });
      }
      return undefined;
    }

    if (ts.isPropertyAccessExpression(expr)) return lowerProperty(expr);

    // `parts[1]`, `rows[i]`, `body["name"]`. Reading out of a value carries whatever
    // was in it, exactly as a property read does — the index chooses WHICH part, not
    // whether the part is trusted.
    //
    // Real code reaches a sink through this constantly, and without it the chain
    // simply stops: `req.body.content.match(re)[1]` into `exec()` is a documented
    // command injection in one of the deliberately vulnerable applications, and it
    // was invisible because of one pair of brackets.
    if (ts.isElementAccessExpression(expr)) {
      const base = lowerExpr(expr.expression);
      if (!base) return undefined;
      const loc = locOf(sf, expr);
      // A LITERAL key is a property name written differently. `body["password"]` and
      // `body.password` are the same access, and recording the first as an anonymous
      // index threw away the only part that says what the field IS -- which is what
      // every rule keyed on a path leaf reads.
      const key = expr.argumentExpression;
      if (ts.isStringLiteralLike(key)) {
        const baseValue = values.find((v) => v.id === base);
        const path = baseValue?.path ? `${baseValue.path}.${key.text}` : key.text;
        const id = newValue("property", loc, { base, path, name: key.text });
        addFlow(base, id, "property", loc);
        return id;
      }
      const id = newValue("property", loc, { base, name: "[index]" });
      addFlow(base, id, "property", loc);
      return id;
    }

    // `new Thing(x)` is a call. Without this, every argument to every constructor
    // vanishes from the dataflow — and one of them is `new Function(src)`, which is
    // an evaluator wearing a different keyword.
    if (ts.isNewExpression(expr)) {
      const loc = locOf(sf, expr);
      const { args, argLiterals, enumeratedOptions } = readArgs(expr.arguments ?? []);

      const callee = resolveCallee(expr);
      const resultId = newValue("call-result", loc, { name: callee.symbol ?? callee.kind });
      calls.push({
        id: `${meta.id}$c${callCount++}`,
        loc,
        callee,
        args,
        argLiterals: Object.keys(argLiterals).length ? argLiterals : undefined,
        argCount: (expr.arguments ?? []).length || undefined,
        enumeratedOptions: enumeratedOptions.length ? enumeratedOptions : undefined,
        resultValueId: resultId,
        block: current,
      });
      return resultId;
    }

    if (ts.isCallExpression(expr)) {
      const loc = locOf(sf, expr);

      const { args, argLiterals, enumeratedOptions } = readArgs(expr.arguments);

      // For a method call, record the receiver separately: taint on the object is
      // how `s.trim()` and `p.then(cb)` carry data, and it is not an argument.
      let method: string | undefined;
      let receiverValueId: string | undefined;
      let receiverType: { type?: string; origin?: string } = {};
      if (ts.isPropertyAccessExpression(expr.expression)) {
        method = expr.expression.name.text;
        receiverValueId = lowerExpr(expr.expression.expression);
        // What the receiver IS, in this language. `delete` and `update` name a
        // database operation and a Map operation equally well, and only the checker
        // can tell them apart. Stated here, judged in the core.
        receiverType = receiverTypeOf(expr.expression.expression);
      }

      const callee = resolveCallee(expr);
      const resultId = newValue("call-result", loc, { name: callee.symbol ?? callee.kind });
      calls.push({
        id: `${meta.id}$c${callCount++}`,
        loc,
        callee,
        args,
        method,
        receiverValueId,
        argLiterals: Object.keys(argLiterals).length ? argLiterals : undefined,
        argCount: expr.arguments.length || undefined,
        enumeratedOptions: enumeratedOptions.length ? enumeratedOptions : undefined,
        receiverType: receiverType.type,
        receiverTypeOrigin: receiverType.origin,
        resultValueId: resultId,
        block: current,
      });
      if (method === "render") lowerRenderedTemplate(expr, args);
      return resultId;
    }

    if (ts.isTemplateExpression(expr)) {
      const loc = locOf(sf, expr);
      const id = newValue("local", loc, { name: "`template`" });
      // The STATIC text of a template is a value too, and dropping it lost the half of
      // the string the program wrote. A rule that asks what a composed value SAYS -- does
      // this statement contain a SQL verb -- could answer for `"SELECT ... " + x` and not
      // for the same statement written as a template, which is how most of it is written.
      const head = expr.head.text;
      if (head) addFlow(newValue("literal", loc, { literal: head }), id, "template", loc);
      for (const span of expr.templateSpans) {
        addFlow(lowerExpr(span.expression), id, "template", loc);
        const tail = span.literal.text;
        if (tail) {
          const at = locOf(sf, span.literal);
          addFlow(newValue("literal", at, { literal: tail }), id, "template", loc);
        }
      }
      return id;
    }

    // A relational test is a fact in its own right: dataflow cannot express that a
    // handler checked one value against another.
    if (ts.isBinaryExpression(expr) && COMPARISON_OPERATORS.has(expr.operatorToken.kind)) {
      const loc = locOf(sf, expr);
      const left = lowerExpr(expr.left);
      const right = lowerExpr(expr.right);
      if (left && right) {
        comparisons.push({
          left,
          right,
          op: expr.operatorToken.getText(sf),
          block: current,
          loc,
        });
      }
      return newValue("local", loc, { name: "comparison" });
    }

    // `req.body.email || ''` is the single most common way real code writes a default,
    // and taint flowed through none of it. The result is whichever side was chosen, so
    // both sides carry into it.
    //
    // The flow kind is "assign" and deliberately NOT "binary": choosing between two
    // values is not composing text out of them. Calling it composition would make
    // `query(req.body.x || '')` look like a built statement to the SQL channel, and
    // would make `axios.get(req.query.url || BASE)` look composed to the channels that
    // require a whole value -- wrong in opposite directions, from one mislabelled hop.
    //
    // OWASP Juice Shop's headline SQL injection interpolates `req.body.email || ''`
    // into a template literal. The template hop was recorded, the value reaching it
    // never was, and the whole flow ended before it started.
    if (ts.isBinaryExpression(expr) && SELECTION_OPERATORS.has(expr.operatorToken.kind)) {
      const loc = locOf(sf, expr);
      const id = newValue("local", loc, { name: "either" });
      addFlow(lowerExpr(expr.left), id, "assign", loc);
      addFlow(lowerExpr(expr.right), id, "assign", loc);
      return id;
    }

    if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const loc = locOf(sf, expr);
      const id = newValue("local", loc, { name: "concat" });
      addFlow(lowerExpr(expr.left), id, "binary", loc);
      addFlow(lowerExpr(expr.right), id, "binary", loc);
      return id;
    }

    if (ts.isConditionalExpression(expr)) {
      const loc = locOf(sf, expr);
      const id = newValue("local", loc, { name: "ternary" });
      addFlow(lowerExpr(expr.whenTrue), id, "assign", loc);
      addFlow(lowerExpr(expr.whenFalse), id, "assign", loc);
      return id;
    }

    if (ts.isSpreadElement(expr)) return lowerExpr(expr.expression);

    if (ts.isArrayLiteralExpression(expr)) {
      const loc = locOf(sf, expr);
      const id = newValue("local", loc, { name: "[array]" });
      for (const el of expr.elements) addFlow(lowerExpr(el), id, "enclose", loc);
      return id;
    }

    if (ts.isObjectLiteralExpression(expr)) {
      const loc = locOf(sf, expr);
      const id = newValue("local", loc, { name: "{object}" });
      // An object literal written AT A CALL is that call's options, and the call-shape
      // rules already read them from the call. Recording its properties as writes too
      // reported one line twice under two numbers -- `mysql.createConnection({password:
      // "hunter2"})` is a password in a connection, which is what the call shape says.
      //
      // An object literal bound to a NAME is configuration, and nothing else reads it.
      // Recorded ONLY for the module's exports, and the number is why. An object
      // literal's keys are not always configuration names: `{members_public_key: "core",
      // admin_session_secret: "core", ...}` is a lookup table from a setting to its
      // group, and reading its keys as names put 1463 findings into a corpus that had
      // 136. `module.exports = { cookieSecret: "..." }` is the one shape where the keys
      // ARE the program's own configuration, and it is the shape a recall audit named.
      const isModuleConfig =
        expr.parent &&
        ts.isBinaryExpression(expr.parent) &&
        expr.parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        expr.parent.right === expr &&
        /^(module\.exports|exports)$/.test(expr.parent.left.getText(sf));
      // Every form that carries a value in. `{ slug }` and `{ ...base }` are how
      // real code builds query objects; handling only `key: value` loses the taint
      // at the last hop before the sink.
      //
      // The kind is "enclose" rather than "assign" because the value became a PART of
      // this object instead of becoming it. `update(req.body)` hands over everything
      // the caller sent; `update({ name: req.body.name })` hands over one field the
      // application chose, and only the first lets a caller set a column nobody meant
      // to expose.
      // What each KEY carries, kept beside the object itself. A template reads its
      // values by name, so linking a render call to the view it renders needs the map
      // from name to value -- and building it here means each initializer is lowered
      // exactly once, which re-reading the object literal later would not.
      const fields = new Map<string, string>();
      for (const prop of expr.properties) {
        if (ts.isPropertyAssignment(prop)) {
          const from = lowerExpr(prop.initializer);
          addFlow(from, id, "enclose", loc);
          const key = ts.isIdentifier(prop.name) || ts.isStringLiteralLike(prop.name)
            ? prop.name.text
            : undefined;
          if (from && key !== undefined) fields.set(key, from);
          // A property given a LITERAL is a value written down under a name, which is
          // the same fact as `config.secret = "..."` and was recorded for one and not
          // the other. `module.exports = { cookieSecret: "..." }` is how a JavaScript
          // application writes its configuration, and a rule that watches writes could
          // not see it at all.
          //
          // Only literals. Recording every property of every object literal would
          // multiply the IR for the sake of a question no rule asks.
          if (
            isModuleConfig &&
            from &&
            key !== undefined &&
            literalOf(prop.initializer) !== undefined
          ) {
            writes.push({ loc: locOf(sf, prop), base: id, path: key, from, block: writeBlock() });
          }
        } else if (ts.isShorthandPropertyAssignment(prop)) {
          // For `{ slug }` the identifier resolves to the PROPERTY symbol, not the
          // local it reads. The checker has a dedicated accessor for the value.
          const valueSym = checker.getShorthandAssignmentValueSymbol(prop);
          const from = valueSym ? bySymbol.get(valueSym) : undefined;
          addFlow(from, id, "enclose", loc);
          if (from) fields.set(prop.name.text, from);
        } else if (ts.isSpreadAssignment(prop)) {
          // A spread is NOT an enclosure. `{ ...req.body }` is the caller's object with
          // extra keys, and every key it had is still a key here -- which is the whole
          // question a rule about "did this arrive whole" is asking. Lowering it as an
          // enclosure said the application had chosen the fields, when it had chosen
          // none of them: Juice Shop's local file read is `res.render(view, { ...req.body,
          // ...themeVars })`, and the layout option a caller sends survives that exactly
          // as it survives passing the body itself.
          addFlow(lowerExpr(prop.expression), id, "assign", loc);
        }
      }
      objectFields.set(id, fields);
      return id;
    }

    if (ts.isStringLiteralLike(expr) || ts.isNumericLiteral(expr)) {
      return newValue("literal", locOf(sf, expr), { literal: expr.text });
    }

    // A regular expression written as a literal is a value with text in it, and the text
    // is the whole of what some rules need to know. It was not lowered at all, so a
    // pattern's own shape -- whether it can be made to backtrack catastrophically -- was
    // outside the engine's reach however plainly it was written.
    if (ts.isRegularExpressionLiteral(expr)) {
      return newValue("literal", locOf(sf, expr), { literal: expr.text });
    }

    // The OPERAND of a unary operator has to be lowered whatever the operator does with
    // it, because that is where the calls are: `if (!pattern.test(input))` is how a great
    // deal of validation is written, and falling through here meant the call was not in
    // the IR at all.
    //
    // What flows OUT depends on the operator. `!x`, `typeof x` and `void x` produce
    // something unrelated to what they were given. `+x` and `-x` are numeric coercion and
    // the MAGNITUDE survives, which is the security-relevant part: `Buffer.alloc(
    // +req.query.size)` is an allocation a caller sizes.
    if (ts.isVoidExpression(expr) || ts.isTypeOfExpression(expr)) {
      lowerExpr(expr.expression);
      return undefined;
    }
    if (ts.isPrefixUnaryExpression(expr)) {
      const inner = lowerExpr(expr.operand);
      switch (expr.operator) {
        case ts.SyntaxKind.PlusToken:
        case ts.SyntaxKind.MinusToken:
          return inner;
      }
      return undefined;
    }

    return undefined;
  };

  /**
   * Reads a call's arguments: the dataflow values, the literals, and the option keys.
   *
   * One definition, used by both `f(x)` and `new F(x)`. It lived only in the call path
   * before, so `new https.Agent({ rejectUnauthorized: false })` carried no literals at
   * all and the option was invisible -- a constructor is where half of Node's
   * configuration is written.
   */
  const readArgs = (
    argNodes: readonly ts.Expression[],
  ): { args: Arg[]; argLiterals: Record<number, string>; enumeratedOptions: number[] } => {
    const args: Arg[] = [];
    const argLiterals: Record<number, string> = {};
    // Keyword slots are numbered from -1 downward, the same encoding the Python frontend
    // uses for `verify=False`. An options object IS JavaScript's keyword argument list,
    // and writing it into the same slot means the core needs no new vocabulary to read
    // one: `{ httpOnly: false }` and `httponly=False` describe the same decision and
    // arrive in the same shape (ADR-001).
    let keyword = 0;
    const enumeratedOptions: number[] = [];

    argNodes.forEach((a, index) => {
      const valueId = lowerExpr(a);
      const fn = resolveFunction(a);
      if (valueId || fn) args.push({ index, valueId, functionId: fn?.id });
      const lit = literalOf(a) ?? constantOf(a) ?? regexTextOf(a);
      if (lit !== undefined) {
        argLiterals[index] = lit;
        return;
      }
      if (!ts.isObjectLiteralExpression(a)) return;

      // Whether the KEY SET is fully known is a separate question from whether the
      // values are. A spread hides keys, so nothing can be concluded from a key not
      // appearing; a computed value hides only itself, and the key is still known to be
      // set. Only the first kind makes this object unenumerable.
      let keysKnown = true;
      for (const prop of a.properties) {
        const named =
          (ts.isPropertyAssignment(prop) || ts.isShorthandPropertyAssignment(prop)) &&
          prop.name !== undefined &&
          (ts.isIdentifier(prop.name) || ts.isStringLiteralLike(prop.name));
        if (!named) {
          keysKnown = false;
          continue;
        }
        const key = (prop.name as ts.Identifier | ts.StringLiteralLike).text;
        // Shorthand `{ httpOnly }` sets the key from a variable: the key is known, the
        // value is not. Recorded as present-with-unknown-value so an absence rule sees
        // it and a value rule does not match it.
        const value = ts.isPropertyAssignment(prop) ? literalOf(prop.initializer) : undefined;
        keyword += 1;
        argLiterals[-keyword] = `${key}=${value ?? "?"}`;

        // One level down. Options that decide something are routinely written inside a
        // named group -- `webPreferences: { nodeIntegration: true }`, `httpsAgent: {
        // rejectUnauthorized: false }`, `cookie: { maxAge: ... }` -- and reading only
        // the top level meant the option was recorded as present-with-unknown-value
        // while the decision sat one line below it. The key keeps its parent so the
        // nesting is visible; matching compares the last segment.
        if (ts.isPropertyAssignment(prop) && ts.isObjectLiteralExpression(prop.initializer)) {
          for (const inner of prop.initializer.properties) {
            if (!ts.isPropertyAssignment(inner) && !ts.isShorthandPropertyAssignment(inner)) continue;
            const iname = inner.name;
            if (!iname || (!ts.isIdentifier(iname) && !ts.isStringLiteralLike(iname))) continue;
            const ikey = (iname as ts.Identifier | ts.StringLiteralLike).text;
            const ivalue = ts.isPropertyAssignment(inner) ? literalOf(inner.initializer) : undefined;
            keyword += 1;
            argLiterals[-keyword] = `${key}.${ikey}=${ivalue ?? "?"}`;
          }
        }
      }
      if (keysKnown) enumeratedOptions.push(index);
    });

    return { args, argLiterals, enumeratedOptions };
  };

  const walk = (n: ts.Node): void => {
    // Nested functions are separate IR functions; their bodies are not inlined here.
    if (n !== node && isFunctionLike(n)) return;

    // A loop body runs an unknown number of times and a switch arm runs or does not,
    // and the block graph says neither: both are lowered straight-line into the
    // enclosing block. Walking them exactly as before, with the position claim on any
    // flow inside suppressed -- see `unmodelled`.
    if (
      ts.isForStatement(n) ||
      ts.isForOfStatement(n) ||
      ts.isForInStatement(n) ||
      ts.isWhileStatement(n) ||
      ts.isDoStatement(n) ||
      ts.isSwitchStatement(n)
    ) {
      unmodelled += 1;
      ts.forEachChild(n, walk);
      unmodelled -= 1;
      return;
    }

    if (ts.isVariableDeclaration(n)) {
      const loc = locOf(sf, n);
      // `for (const entry of files)` declares a variable with no initializer, and the
      // collection it reads from is two nodes up. Without this the chain simply stopped
      // at the loop: an array of objects a caller sent produced elements related to
      // nothing, and every judgement about what the loop did with them was silent.
      //
      // Lowered as a property read rather than an enclosure, because that is the
      // direction it goes -- an element comes OUT of the collection, and it comes out
      // whole.
      // for-OF only. A for-in binding is a property NAME, not a value, and the two are
      // different things: `for (const i in req.body.items)` binds "0" and "1", and
      // marking those as arbitrary caller text would report an array index as an
      // injection. A key that IS caller-chosen is a real shape and needs its own rule,
      // not this one.
      const iterated =
        n.parent &&
        ts.isVariableDeclarationList(n.parent) &&
        n.parent.parent &&
        ts.isForOfStatement(n.parent.parent)
          ? n.parent.parent.expression
          : undefined;
      const init = n.initializer
        ? lowerExpr(n.initializer)
        : iterated
          ? lowerExpr(iterated)
          : undefined;
      const kind = n.initializer || !iterated ? "assign" : "property";

      if (ts.isIdentifier(n.name)) {
        const id = newValue("local", loc, { name: n.name.text });
        bind(n.name, id);
        addFlow(init, id, kind, loc);
        return;
      }

      // Destructuring binds names too, and it binds them to a PATH. Emitting a
      // plain assignment loses that path, so `const { body: { target } } = req`
      // would produce a value with no relationship to `req.body` and no source
      // would ever match it.
      for (const bound of bindingPaths(n.name)) {
        const bloc = locOf(sf, bound.name);
        const id = init
          ? newValue("property", bloc, {
              name: bound.name.text,
              base: init,
              path: bound.path.join("."),
            })
          : newValue("local", bloc, { name: bound.name.text });
        bind(bound.name, id);
        addFlow(init, id, "property", bloc);
      }
      return;
    }
    // A catch binding is where internal error detail enters the program. Without a
    // value for it, the most common information-exposure flow has no source.
    // A CATCH is a different path, not the next statement.
    //
    // Lowering try/catch as straight-line code put the catch handler's calls into a block
    // that unavoidably follows the try body -- so `try { ...; res.sendStatus(401) } catch
    // (e) { next(e) }` looked like a rejection the handler carried on past. It is not: the
    // catch runs instead of the rest, not after it.
    //
    // The finally block is the one part that IS unavoidable, and it is linked from both.
    if (ts.isTryStatement(n)) {
      const tryBlock = newBlock(n.tryBlock);
      link(current, tryBlock);
      current = tryBlock;
      walk(n.tryBlock);
      const tryEnd = current;

      let catchEnd: string | undefined;
      if (n.catchClause) {
        const catchBlock = newBlock(n.catchClause);
        // From the START of the try: an exception can be raised anywhere inside it.
        link(tryBlock, catchBlock);
        current = catchBlock;
        walk(n.catchClause);
        catchEnd = current;
      }

      const after = newBlock(n);
      if (n.finallyBlock) {
        const finallyBlock = newBlock(n.finallyBlock);
        link(tryEnd, finallyBlock);
        if (catchEnd) link(catchEnd, finallyBlock);
        current = finallyBlock;
        walk(n.finallyBlock);
        link(current, after);
      } else {
        link(tryEnd, after);
        if (catchEnd) link(catchEnd, after);
      }
      current = after;
      return;
    }
    if (ts.isCatchClause(n)) {
      const decl = n.variableDeclaration;
      if (decl && ts.isIdentifier(decl.name)) {
        const loc = locOf(sf, decl);
        const id = newValue("catch-param", loc, { name: decl.name.text });
        bind(decl.name, id);
      }
      walk(n.block);
      return;
    }
    // Conditions are not statements, so they are never reached by the statement walk
    // on their own. The condition belongs to the block that branches on it.
    if (ts.isIfStatement(n)) {
      lowerExpr(n.expression);
      const branch = current;
      terminate(branch, "branch");

      const thenBlock = newBlock(n.thenStatement);
      link(branch, thenBlock);
      current = thenBlock;
      walk(n.thenStatement);
      const thenEnd = current;

      let elseEnd: string | null = null;
      if (n.elseStatement) {
        const elseBlock = newBlock(n.elseStatement);
        link(branch, elseBlock);
        current = elseBlock;
        walk(n.elseStatement);
        elseEnd = current;
      }

      const after = newBlock(n);
      if (!leaves(thenEnd)) link(thenEnd, after);
      if (elseEnd === null) link(branch, after);
      else if (!leaves(elseEnd)) link(elseEnd, after);

      current = after;
      return;
    }
    if (ts.isReturnStatement(n)) {
      if (n.expression) {
        const v = lowerExpr(n.expression);
        if (v) returns.push(v);
      }
      terminate(current, "return");
      current = newBlock(n);
      return;
    }
    if (ts.isThrowStatement(n)) {
      lowerExpr(n.expression);
      terminate(current, "throw");
      current = newBlock(n);
      return;
    }
    // A call the LANGUAGE says does not return. `never` is TypeScript's own statement of
    // exactly the fact a control-flow question needs: `NcError.forbidden(msg): never`
    // throws, so nothing after it runs -- and a graph that did not know went on to report
    // fifty-one rejections in one repository as though the handler continued past them.
    //
    // Read from the checker rather than from a list of names, because that is the whole
    // point of having one: the frontend answers what the language knows, and the core
    // asks what the answer means (ADR-001).
    if (
      ts.isExpressionStatement(n) &&
      ts.isCallExpression(n.expression) &&
      returnsNever(n.expression)
    ) {
      lowerExpr(n.expression);
      terminate(current, "throw");
      current = newBlock(n);
      return;
    }
    // `query += "..." + id` is composition written as a statement, and it was handled by
    // nothing: not the expression lowering, which reads `+` and not `+=`, and not the
    // assignment branch below, which reads `=`. A statement that builds a string one
    // piece at a time is how a long query gets written, and the pieces went nowhere.
    if (
      ts.isExpressionStatement(n) &&
      ts.isBinaryExpression(n.expression) &&
      n.expression.operatorToken.kind === ts.SyntaxKind.PlusEqualsToken
    ) {
      const added = lowerExpr(n.expression.right);
      const existing = lowerExpr(n.expression.left);
      // The result is the two halves joined and it lands back under the same name, so
      // the composition edge goes INTO the value the name already has.
      if (existing) addFlow(added, existing, "binary", locOf(sf, n));
      return;
    }

    // An assignment INTO something: `session.user = x`, `config["debug"] = y`. Only
    // assignments to a plain name were lowered, so writing into a property recorded
    // nothing -- and putting caller data into a session is a weakness whose entire shape
    // is the write.
    if (
      ts.isExpressionStatement(n) &&
      ts.isBinaryExpression(n.expression) &&
      n.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken
    ) {
      const target = n.expression.left;
      const from = lowerExpr(n.expression.right);
      if (ts.isPropertyAccessExpression(target)) {
        writes.push({
          loc: locOf(sf, n),
          base: lowerExpr(target.expression),
          path: target.name.text,
          from,
          block: writeBlock(),
        });
        return;
      }
      if (ts.isElementAccessExpression(target)) {
        const key = target.argumentExpression;
        const literalKey = ts.isStringLiteralLike(key);
        // A COMPUTED key is recorded as a value, because how many entries a container
        // can come to hold is decided by how many distinct keys reach it -- and a key
        // the caller chose has no ceiling. A literal key is a property name spelled
        // differently and belongs in `path` where every other fixed name goes.
        writes.push({
          loc: locOf(sf, n),
          base: lowerExpr(target.expression),
          path: literalKey ? key.text : undefined,
          key: literalKey ? undefined : lowerExpr(key),
          from,
          block: writeBlock(),
        });
        return;
      }
      // A plain name that was DECLARED somewhere else. Inside a request handler that is
      // state the whole process shares, so what one caller put there is what the next
      // caller gets. The declaration's position is the whole evidence: a name declared in
      // this function is a local and touches nothing outside it.
      if (ts.isIdentifier(target) && !ts.isSourceFile(node) && declaredOutside(target)) {
        writes.push({
          loc: locOf(sf, n),
          base: bySymbol.get(checker.getSymbolAtLocation(target)!),
          path: target.text,
          from,
          block: writeBlock(),
          scope: "process",
        });
        lowerExpr(n.expression);
        return;
      }
      // An assignment to a name that was never DECLARED. In JavaScript that creates a
      // global -- process-wide state, and a value the rest of the program can read -- and
      // without a binding for it the value went nowhere at all.
      //
      // dvna writes `output = { searchTerm: req.body.name }` inside a callback and renders
      // it, so an entire flow from a request to an unescaped interpolation hung on a
      // missing `const`.
      if (ts.isIdentifier(target) && !ts.isSourceFile(node) && undeclaredName(target)) {
        let id = fileGlobals.get(target.text);
        if (!id) {
          id = newValue("local", locOf(sf, target), { name: target.text });
          fileGlobals.set(target.text, id);
        }
        bind(target, id);
        addFlow(from, id, "assign", locOf(sf, n));
        writes.push({ loc: locOf(sf, n), base: id, path: target.text, from, block: writeBlock(), scope: "process" });
        return;
      }
      // A plain name declared in THIS function and assigned again. `var cart = null;`
      // followed by `cart = {...}` inside a try block is ordinary JavaScript, and the
      // second statement produced nothing at all: an `=` is not one of the operators
      // lowerExpr reads, so neither side was visited and the value never reached the
      // name. One vulnerable application hid a SQL injection and a catastrophic regular
      // expression behind that single missing edge.
      if (ts.isIdentifier(target)) {
        const sym = checker.getSymbolAtLocation(target);
        const existing = sym ? bySymbol.get(sym) : undefined;
        if (existing) {
          addFlow(from, existing, "assign", locOf(sf, n));
          return;
        }
      }
    }

    if (ts.isExpressionStatement(n)) {
      lowerExpr(n.expression);
      return;
    }
    ts.forEachChild(n, walk);
  };

  // A module's top level is code like any other, and it is where configuration lives:
  // `app.use(cors({ origin: true, credentials: true }))` is never inside a function.
  // Lowering it as a function of its own means every analysis kind can see it without
  // learning a new shape. The statement walk already stops at function boundaries, so
  // nothing nested is counted twice.
  if (ts.isSourceFile(node)) {
    walk(node);
    return {
      id: meta.id,
      name: meta.name,
      module: meta.moduleId,
      loc: locOf(sf, node),
      params,
      values,
      flows,
      calls,
      returns,
      comparisons,
      // Writes too. They were computed here and then dropped on the way out, which is
      // the worst place to drop them: this branch exists BECAUSE a module's top level is
      // where configuration lives, and `module.exports = { cookieSecret: "..." }` is a
      // write and nothing else.
      writes: writes.length ? writes : undefined,
      entryBlock,
      blocks,
    };
  }

  const body = (node as ts.FunctionLikeDeclaration).body;
  if (body) {
    if (ts.isBlock(body)) {
      walk(body);
    } else {
      const v = lowerExpr(body);
      if (v) returns.push(v);
    }
  }

  return {
    id: meta.id,
    name: meta.name,
    module: meta.moduleId,
    loc: locOf(sf, node),
    params,
    values,
    flows,
    calls,
    returns,
    comparisons,
    writes: writes.length ? writes : undefined,
    entryBlock,
    blocks,
  };
}

// --- helpers --------------------------------------------------------------

interface BoundName {
  name: ts.Identifier;
  path: string[];
}

/**
 * Every identifier a destructuring pattern binds, with the property path it reads.
 * `const { body: { target } } = req` binds `target` at path body.target.
 */
function bindingPaths(name: ts.BindingName, prefix: string[] = []): BoundName[] {
  if (ts.isIdentifier(name)) return [{ name, path: prefix }];

  const out: BoundName[] = [];
  for (const element of name.elements) {
    if (!ts.isBindingElement(element)) continue;

    let segment: string | undefined;
    const key = element.propertyName ?? (ts.isIdentifier(element.name) ? element.name : undefined);
    if (key && (ts.isIdentifier(key) || ts.isStringLiteral(key))) segment = key.text;

    out.push(...bindingPaths(element.name, segment ? [...prefix, segment] : prefix));
  }
  return out;
}

function locOf(sf: ts.SourceFile, node: ts.Node): Loc {
  const pos = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return {
    file: sf.fileName,
    line: pos.line + 1,
    column: pos.character + 1,
  };
}

function isUnder(rootDir: string, file: string): boolean {
  const rel = path.relative(path.resolve(rootDir), path.resolve(file));
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

// Memoized because this is called once per source location, and a large program has
// millions of them across a handful of distinct files. Profiling a monorepo scan put
// ~11% of total runtime inside path.resolve/relative/normalizeString reached from here,
// all of it recomputing the same few hundred answers.
const moduleIdCache = new Map<string, string>();

function moduleIdOf(rootDir: string, file: string): string {
  // Idempotent by design: some paths reach the IR already root-relative and some
  // arrive absolute from the compiler, and the caller cannot always tell which.
  // Resolving a relative path here would silently resolve it against the process
  // working directory and produce a path that points nowhere.
  if (!path.isAbsolute(file)) return file;

  const key = `${rootDir}\u0000${file}`;
  const hit = moduleIdCache.get(key);
  if (hit !== undefined) return hit;

  const id = path.relative(path.resolve(rootDir), path.resolve(file)).split(path.sep).join("/");
  moduleIdCache.set(key, id);
  return id;
}

/** Rewrites absolute paths in locations to be relative to rootDir. */
export function relativizeLocations(doc: IRDoc, rootDir: string): IRDoc {
  // Rewrites in place rather than rebuilding. The document was constructed moments ago
  // by this process and nothing else holds a reference to any of it, so the spread-copy
  // this used to do bought no safety and allocated a fresh object for every value, flow,
  // call, comparison and block in the program. On a monorepo that is millions of
  // short-lived objects and the garbage collector to go with them.
  const rel = (loc: Loc | undefined): void => {
    if (loc) loc.file = moduleIdOf(rootDir, loc.file);
  };

  for (const m of doc.modules) {
    m.path = moduleIdOf(rootDir, m.path);
  }

  for (const fn of doc.functions) {
    rel(fn.loc);
    for (const v of fn.values) rel(v.loc);
    for (const f of fn.flows) rel(f.loc);
    for (const c of fn.calls) rel(c.loc);
    for (const c of fn.comparisons ?? []) rel(c.loc);
    for (const w of fn.writes ?? []) rel(w.loc);
    for (const b of fn.blocks ?? []) rel(b.loc);
  }

  for (const ep of doc.entryPoints) {
    rel(ep.loc);
    // Every path that leaves the frontend must be root-relative, not only the ones that
    // existed when this was written. An absolute path here is not cosmetic: it puts the
    // checkout directory into group names and finding evidence, so the same code scanned
    // on two machines produces two different reports and no finding can be matched to
    // its previous self.
    if (ep.detail?.module) ep.detail.module = moduleIdOf(rootDir, ep.detail.module);
    for (const mw of ep.middleware ?? []) rel(mw.loc);
  }

  return doc;
}
