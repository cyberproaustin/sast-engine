// Express framework model.
//
// v0 encodes this as code because the declarative model format does not exist yet.
// It is deliberately isolated in its own module so that externalizing it (ADR-004)
// is a move rather than an untangling. Nothing in lower.ts knows Express exists.

import ts from "typescript";
import type { EntryPoint, MiddlewareRef } from "./ir.ts";
import { collectStringBindings, isUnresolvedPath, joinRoute, pathText, unresolvedPath } from "./routepath.ts";
import type { RegistryResolver } from "./registry.ts";

/** `require("express")` written inline, without an intermediate binding. */
function requiresExpress(expr: ts.Expression): boolean {
  return (
    ts.isCallExpression(expr) &&
    ts.isIdentifier(expr.expression) &&
    expr.expression.text === "require" &&
    expr.arguments.length > 0 &&
    ts.isStringLiteralLike(expr.arguments[0]) &&
    expr.arguments[0].text === "express"
  );
}

/** Packages whose default export is a router factory. */
const ROUTER_MODULES = new Set(["koa-router", "@koa/router", "express-promise-router", "router"]);

/**
 * Whether a module hands out request-handler REGISTRARS that answer nothing on the
 * network.
 *
 * Mock Service Worker is written `http.post("/api/drive/files", async ({ request }) =>
 * ...)`, which is the same four tokens as a route registration and means the opposite:
 * the handler answers a fetch the browser makes to itself inside a component story. One
 * repository contributed 58 of these to a surface of 141 -- 41% of what the engine
 * claimed the application answered was a Storybook mock -- and the receiver `http` is
 * exactly the case where a type cannot be resolved, so nothing downstream could have
 * caught it.
 *
 * The import is the whole of the evidence and it is decisive, which is the same shape
 * the supertest exclusion has: `server.post("/api/x", {body})` is a REQUEST written like
 * a registration, and it is told apart by what the arguments are rather than by where
 * they sit.
 */
function isMockRegistrar(module: string): boolean {
  return module === "msw" || module.startsWith("msw/");
}

/**
 * A Storybook story, or the mock support beside it.
 *
 * Independent of the import, because a story that pulls its handlers out of a shared
 * `mocks.js` registers them under a name this file never imported from `msw`. Over-
 * reporting the surface is worse than under-reporting it (ADR-009): a phantom route
 * makes every count downstream a lie, and no application serves its production API out
 * of `.storybook/` or a `*.stories.*` file.
 */
function isMockModule(fileName: string): boolean {
  const path = fileName.replace(/\\/g, "/");
  return /(^|\/)\.storybook\//.test(path) || /\.stories\./.test(path);
}

const ROUTE_METHODS = new Set([
  "get",
  "post",
  "put",
  "patch",
  "delete",
  "head",
  "options",
  "all",
]);

export interface ImportRef {
  module: string;
  export: string;
}

export interface FuncRef {
  id: string;
  name: string;
}

export type ResolveFunction = (node: ts.Node) => FuncRef | undefined;

/**
 * What this file cannot know on its own.
 *
 * Both answers are program-wide by nature -- the collection a registration loop walks is
 * declared in another module, and the prefix a plugin's routes are served under is stated
 * by whoever registered the plugin, never by the file holding the routes. They are passed
 * in rather than looked up here because nothing in this model may reach for a checker
 * (ADR-004): the framework model states the shape, the caller supplies the facts.
 */
export interface ProgramFacts {
  /** The names a statically enumerable collection holds. */
  resolveRegistry?: RegistryResolver;
  /** The prefix a plugin registration puts in front of everything this node registers. */
  prefixOf?: (node: ts.Node) => string;
}

/**
 * Finds Express route registrations and returns each handler as an HTTP entry point,
 * along with the middleware chain applied to it. Resolution is structural (import of
 * "express" -> app binding -> app.<method>(...)), so it does not depend on Express
 * types being installed.
 */
export function detectExpressRoutes(
  sf: ts.SourceFile,
  imports: Map<string, ImportRef>,
  resolveFunction: ResolveFunction,
  locOf: (node: ts.Node) => { file: string; line: number; column: number },
  program?: ProgramFacts,
): EntryPoint[] {
  if (isMockModule(sf.fileName)) return [];

  const expressNames = new Set<string>();
  const routerNames = new Set<string>();
  const mockNames = new Set<string>();
  for (const [local, ref] of imports) {
    if (isMockRegistrar(ref.module)) mockNames.add(local);
  }
  for (const [local, ref] of imports) {
    // Koa's router is the same shape from a different package, and it is what several
    // large applications are built on. `import Router from "koa-router"` then `new
    // Router()` registers routes exactly as Express does -- and named ones besides,
    // where the first argument is a route NAME rather than a path.
    const isRouterModule = ROUTER_MODULES.has(ref.module) || /(^|[/@-])router$/.test(ref.module);
    if (ref.module !== "express" && !isRouterModule) continue;
    expressNames.add(local);
    // `const { Router } = require("express")` binds the factory directly, and a default
    // import from a router package is the factory itself.
    if (ref.export === "Router" || (isRouterModule && ref.export === "default")) {
      routerNames.add(local);
    }
  }
  // No early exit on an empty binding set: `require("express").Router()` names
  // express inline and produces no import binding at all, which is how a good deal
  // of CommonJS code is written.
  const appNames = collectAppBindings(sf, expressNames, routerNames);
  // A route registered on something Fastify made is a FASTIFY route. The registration
  // is spelled exactly as Express's -- `x.get(path, handler)` -- so the shape cannot
  // tell them apart and the RECEIVER has to, which is the same move the Python side
  // made when it took a framework from the decorator's receiver rather than from the
  // decorator's name. It matters beyond the label: the framework is what selects the
  // source rules that seed a handler's parameters, so one application's 83 routes were
  // all being seeded with Express's request shape.
  const fastifyNames = collectFastifyBindings(sf, imports);
  for (const name of fastifyNames) appNames.add(name);
  // Routers reach a module as a PARAMETER constantly — `module.exports = (app) =>
  // { app.get(...) }`. There is no binding to find, so recognize the shape instead:
  // a route-method call whose first argument is a path literal. This keys on
  // structure rather than on the receiver being named "app" (ADR-010).
  const shaped = collectRouterShapes(sf);
  for (const name of shaped) appNames.add(name);
  // Removed last, and per identifier rather than per file: a module is entitled to mock
  // one API and serve another, and only the name the mock library handed it is barred.
  for (const name of mockNames) appNames.delete(name);
  if (appNames.size === 0) return [];

  // Names bound to an expression anywhere in this file, so a path written as a template
  // or a constant resolves to the address it is served at.
  const consts = collectStringBindings(sf);
  // Where a router in this file is mounted: `app.use("/api", router)` puts every route
  // registered on `router` below `/api`, and a path recorded without that prefix names an
  // address that answers nothing.
  const mounts = collectMountPrefixes(sf, appNames, consts);

  // Application-wide middleware. Path scoping and registration order are not modeled
  // yet, so this is attributed to every route on the same binding; that is why it is
  // recorded with scope "app" rather than merged into the route chain.
  const appMiddleware: MiddlewareRef[] = [];
  const entryPoints: EntryPoint[] = [];
  // Addresses this file has already expanded a loop into. The registry loop that
  // motivated this registers in TWO branches -- `requireFile` or not -- so every one of
  // its 438 names is registered twice under one condition, and emitting both would
  // report 876 addresses where the application answers at 438. An address exists once
  // however many implementations sit behind it, and the surface counts addresses.
  const registered = new Set<string>();

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const target = node.expression.expression;
      const method = node.expression.name.text;
      // A CHAIN registers several routes on one receiver: `router.post(a, h1).post(b,
      // h2).get(c, h3)`. Every call after the first has a CallExpression for a receiver,
      // so requiring an identifier found the first route of each chain and lost the rest
      // -- 83 of one application's 287.
      const root = chainRoot(target);
      if (root && appNames.has(root.text)) {
        if (method === "use") {
          appMiddleware.push(...middlewareFrom(node, "app", resolveFunction, locOf));
          const mount = staticMount(node, consts, locOf);
          if (mount) entryPoints.push(mount);
        } else if (ROUTE_METHODS.has(method)) {
          // `fastify.register(plugin, { prefix: '/api' })` is a mount stated in another
          // file entirely, and a route recorded without it names an address that answers
          // nothing -- 438 of them, in the application this was measured on.
          const prefix = joinRoute(program?.prefixOf?.(node) ?? "", mounts.get(root.text) ?? "");
          const chained = chainRoutePath(target, consts);
          entryPoints.push(
            ...routesFrom(
              node,
              method,
              prefix,
              chained,
              consts,
              fastifyNames.has(root.text) ? "fastify" : "express",
              chained === undefined
                ? loopExpansion(node, consts, program?.resolveRegistry, registered)
                : undefined,
              resolveFunction,
              locOf,
            ),
          );
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  if (appMiddleware.length === 0) return entryPoints;
  return entryPoints.map((ep) => ({
    ...ep,
    middleware: [...appMiddleware, ...(ep.middleware ?? [])],
  }));
}

/**
 * A directory the application serves as files, which is surface with no handler in it.
 *
 * A mount is not a method registration and was therefore not enumerated at all: three
 * addresses in one repository here -- the built frontend, an upload directory and a
 * screenshot directory -- that answer a caller and appear nowhere in a surface an
 * operator is meant to audit. ADR-009 says a route that exists must appear, and the
 * ADDRESS is what exists; there is no callback to name and none is invented.
 *
 * Recognized by the middleware's own spelling. `express.static`, `serveStatic` and
 * `expressStaticGzip` all end in the word, which is the only thing three packages agree
 * on -- and a name ending in `static` that is not a file server is not something anybody
 * writes.
 */
function staticMount(
  node: ts.CallExpression,
  consts: Map<string, ts.Expression>,
  locOf: (node: ts.Node) => { file: string; line: number; column: number },
): EntryPoint | undefined {
  let served: ts.CallExpression | undefined;
  for (const arg of node.arguments) {
    if (!ts.isCallExpression(arg)) continue;
    const callee = arg.expression;
    const name = ts.isPropertyAccessExpression(callee)
      ? callee.name.text
      : ts.isIdentifier(callee)
        ? callee.text
        : "";
    if (/static/i.test(name)) served = arg;
  }
  if (!served) return undefined;
  const first = node.arguments[0];
  const path = first && first !== served ? pathText(first, consts) : "/";
  const root = served.arguments[0] ? textOfNode(served.arguments[0]) : "";
  return {
    functionId: "",
    kind: "static-mount",
    framework: "express",
    detail: { path, ...(root ? { root } : {}) },
    loc: locOf(node),
  };
}

/** What an expression was written as, trimmed for a detail field. */
function textOfNode(node: ts.Node): string {
  if (ts.isStringLiteralLike(node)) return node.text;
  const t = node.getText(node.getSourceFile()).replace(/\s+/g, " ");
  return t.length > 60 ? t.slice(0, 57) + "..." : t;
}

/** Identifiers bound to an Express app or router: `const app = express()`. */
function collectAppBindings(
  sf: ts.SourceFile,
  expressNames: Set<string>,
  routerNames: Set<string>,
): Set<string> {
  const bindings = new Set<string>();

  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      // `new Router()` as well as `Router()`. Koa's router is constructed and Express's
      // is called, and looking only for the call left every Koa application's routes
      // unenumerated.
      (ts.isCallExpression(node.initializer) || ts.isNewExpression(node.initializer)) &&
      isExpressFactory(node.initializer.expression, expressNames, routerNames)
    ) {
      bindings.add(node.name.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  return bindings;
}

/**
 * Prefixes declared by plugin registrations: `fastify.register(routes, { prefix: '/api' })`.
 *
 * Everything the registered function registers is served under that prefix, and the
 * function is in another file which never states it. The alternative to reading this is
 * an application whose entire API is enumerated one segment short -- 438 addresses in
 * the tree that motivated it, every one of them wrong in the same way.
 *
 * Keyed by the function, so the answer travels with the registrations rather than with
 * the file. A function registered twice under DIFFERENT prefixes is recorded as ambiguous
 * and gets none: two mounts is a fact this shape cannot express in one row, and choosing
 * one of them would state an address the reader could not check.
 */
export function collectPluginPrefixes(
  sf: ts.SourceFile,
  resolveFunction: ResolveFunction,
  out: Map<string, string>,
): void {
  const consts = collectStringBindings(sf);
  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "register" &&
      node.arguments.length >= 2 &&
      ts.isObjectLiteralExpression(node.arguments[1])
    ) {
      let prefix = "";
      for (const prop of node.arguments[1].properties) {
        if (!ts.isPropertyAssignment(prop) || prop.name.getText(sf) !== "prefix") continue;
        const text = pathText(prop.initializer, consts);
        if (!isUnresolvedPath(text)) prefix = text;
      }
      const plugin = prefix ? resolveFunction(node.arguments[0]) : undefined;
      if (plugin) {
        const seen = out.get(plugin.id);
        out.set(plugin.id, seen === undefined || seen === prefix ? prefix : "");
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

/**
 * Identifiers holding a Fastify server, by the two ways one arrives in a file.
 *
 * `const fastify = Fastify()` is the same evidence `const app = express()` is: the
 * factory came from the framework's own module and this name holds what it made.
 *
 * The other way is a PARAMETER, and it is how nearly every Fastify application above
 * a single file is written -- `fastify.register(plugin)` hands the instance to a
 * function that registers on it. There is no binding to watch being created, so the
 * evidence is the declared type: a parameter annotated `FastifyInstance`, where that
 * name was imported from `fastify`. One application registers 8 of its route files
 * this way, and two of them (`NodeinfoServerService`) state every path as a local
 * constant, so nothing in the file looked like a route at all.
 *
 * The TYPE and not the parameter's name: `fastify` is what the parameter happens to be
 * called in that application, and keying on a name would be the mistake this whole fix
 * is about (ADR-010).
 */
function collectFastifyBindings(sf: ts.SourceFile, imports: Map<string, ImportRef>): Set<string> {
  const factories = new Set<string>();
  const instanceTypes = new Set<string>();
  for (const [local, ref] of imports) {
    if (ref.module !== "fastify") continue;
    if (ref.export === "default" || ref.export === "fastify") factories.add(local);
    if (ref.export === "FastifyInstance") instanceTypes.add(local);
  }
  if (factories.size === 0 && instanceTypes.size === 0) return new Set<string>();

  const out = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      (ts.isCallExpression(node.initializer) || ts.isNewExpression(node.initializer)) &&
      ts.isIdentifier(node.initializer.expression) &&
      factories.has(node.initializer.expression.text)
    ) {
      out.add(node.name.text);
    }
    if (
      ts.isParameter(node) &&
      ts.isIdentifier(node.name) &&
      node.type &&
      ts.isTypeReferenceNode(node.type) &&
      ts.isIdentifier(node.type.typeName) &&
      instanceTypes.has(node.type.typeName.text)
    ) {
      out.add(node.name.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  return out;
}

/**
 * Where each router in this file is mounted: `app.use("/api/v2", router)`.
 *
 * Only what is decidable HERE. A router required across a module boundary --
 * `app.use("/api", require("./routes"))` -- is mounted at a prefix this file states and
 * registered in a file that never sees it, and joining those two halves needs a
 * program-wide pass the frontend does not have yet. That limit is stated rather than
 * papered over (ADR-003): the routes still appear, at the path their own file spells.
 */
function collectMountPrefixes(
  sf: ts.SourceFile,
  appNames: Set<string>,
  consts: Map<string, ts.Expression>,
): Map<string, string> {
  const out = new Map<string, string>();

  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "use" &&
      node.arguments.length >= 2
    ) {
      // The MOUNTED thing has to be a router this file watched being created. Every
      // other second argument of `use` is middleware, and giving middleware a mount
      // prefix would move routes that were never registered on it.
      const mounted = node.arguments[node.arguments.length - 1];
      if (ts.isIdentifier(mounted) && appNames.has(mounted.text) && !out.has(mounted.text)) {
        const prefix = pathText(node.arguments[0], consts);
        if (prefix) out.set(mounted.text, prefix);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  return out;
}

/** Identifiers used like a router: `x.get("/path", ...)`. */
function collectRouterShapes(sf: ts.SourceFile): Set<string> {
  const out = new Set<string>();

  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      ROUTE_METHODS.has(node.expression.name.text) &&
      node.arguments.length >= 2
    ) {
      const first = node.arguments[0];
      const last = node.arguments[node.arguments.length - 1];
      // A path literal is what distinguishes a route registration from `map.get(k)`
      // or `cache.delete(k)` -- and it is not enough on its own. A test client is
      // called the same way: `server.post("/api/x", { body })` has a path literal and
      // two arguments, and admitting the name on that evidence turned 228 routes into
      // 1475 in one repository. Nearly every one of them was a request in a test.
      //
      // A registration ENDS IN A HANDLER. This is inference rather than a binding the
      // frontend watched being created, so it is held to the stricter standard: the
      // last argument must be something that could be a function.
      if (ts.isStringLiteralLike(first) && first.text.startsWith("/") && couldBeHandler(last)) {
        out.add(node.expression.expression.text);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  return out;
}

/** The identifier a call chain is rooted at: `router` in `router.post(...).get(...)`. */
function chainRoot(expr: ts.Expression): ts.Identifier | undefined {
  let cur: ts.Expression = expr;
  for (let hops = 0; hops < 16; hops++) {
    if (ts.isIdentifier(cur)) return cur;
    if (ts.isCallExpression(cur)) {
      cur = cur.expression;
      continue;
    }
    if (ts.isPropertyAccessExpression(cur)) {
      cur = cur.expression;
      continue;
    }
    return undefined;
  }
  return undefined;
}

/**
 * The path a `.route(...)` in the receiver chain already stated, if there is one.
 *
 * `router.route("/things").get(handler).post(handler)` puts the path on a call of its
 * own, so the verb calls have NO path argument and their first argument is the handler.
 * Reading the path off the chain is what tells those two shapes apart -- and it recovers
 * a path that was being recorded as `*` for every route registered this way.
 */
function chainRoutePath(
  expr: ts.Expression,
  consts: Map<string, ts.Expression>,
): string | undefined {
  let cur: ts.Expression = expr;
  for (let hops = 0; hops < 16; hops++) {
    if (ts.isCallExpression(cur)) {
      if (
        ts.isPropertyAccessExpression(cur.expression) &&
        cur.expression.name.text === "route" &&
        cur.arguments.length > 0
      ) {
        return pathText(cur.arguments[0], consts);
      }
      cur = cur.expression;
      continue;
    }
    if (ts.isPropertyAccessExpression(cur)) {
      cur = cur.expression;
      continue;
    }
    return undefined;
  }
  return undefined;
}

/** A function, or a name that might hold one. Not an object, array or literal. */
function couldBeHandler(node: ts.Expression | undefined): boolean {
  if (!node) return false;
  return (
    ts.isArrowFunction(node) ||
    ts.isFunctionExpression(node) ||
    ts.isIdentifier(node) ||
    ts.isPropertyAccessExpression(node) ||
    ts.isCallExpression(node)
  );
}

function isExpressFactory(
  expr: ts.Expression,
  expressNames: Set<string>,
  routerNames: Set<string>,
): boolean {
  if (ts.isIdentifier(expr)) return expressNames.has(expr.text) || routerNames.has(expr.text);
  if (requiresExpress(expr)) return true;

  // express.Router(), and `require("express").Router()` written inline.
  if (ts.isPropertyAccessExpression(expr) && expr.name.text === "Router") {
    if (ts.isIdentifier(expr.expression)) return expressNames.has(expr.expression.text);
    return requiresExpress(expr.expression);
  }
  return false;
}

/** Function-valued arguments of a call, as middleware references. */
/** How the source spelled this argument: `requireAuth` or `auth.optional`. */
function writtenName(arg: ts.Expression): string | undefined {
  if (ts.isIdentifier(arg)) return arg.text;
  if (ts.isPropertyAccessExpression(arg)) {
    return `${arg.expression.getText(arg.getSourceFile())}.${arg.name.text}`;
  }
  return undefined;
}

function middlewareFrom(
  call: ts.CallExpression,
  scope: string,
  resolveFunction: ResolveFunction,
  locOf: (node: ts.Node) => { file: string; line: number; column: number },
  limit = Number.MAX_SAFE_INTEGER,
): MiddlewareRef[] {
  const out: MiddlewareRef[] = [];
  for (let i = 0; i < Math.min(call.arguments.length, limit); i++) {
    const arg = call.arguments[i];
    const ref = resolveFunction(arg);
    if (ref) {
      // Identity comes from the resolved function; the NAME comes from how the code
      // spelled it. `module.exports.isAuthenticated = function (...)` resolves to an
      // anonymous function expression, and a surface listing eleven controls all
      // called `<anonymous>` is unreadable — which matters, because the surface is
      // what an operator checks their application against (ADR-009).
      out.push({ functionId: ref.id, name: writtenName(arg) ?? ref.name, scope, loc: locOf(arg) });
      continue;
    }
    // An unresolved binding is still comparable: convention analysis only needs to
    // know that peers share it, not what it does. `auth.optional` is the common
    // real-world shape and must not vanish just because it is a property access.
    if (ts.isIdentifier(arg)) {
      out.push({ symbol: arg.text, name: arg.text, scope, loc: locOf(arg) });
    } else if (ts.isPropertyAccessExpression(arg)) {
      const text = `${arg.expression.getText(arg.getSourceFile())}.${arg.name.text}`;
      out.push({ symbol: text, name: text, scope, loc: locOf(arg) });
    }
  }
  return out;
}

/**
 * The addresses a registration inside a `for ... of` loop actually serves.
 *
 * `for (const endpoint of endpoints) fastify.all('/' + endpoint.name, handler)` is one
 * call site and 438 addresses, and the collection is knowable: it is a module's own
 * re-exports walked with `Object.entries`. Where the collection resolves, the path is
 * folded once per element; where it does not, this answers nothing and the caller keeps
 * the single `<unresolved:...>` row it would have recorded anyway.
 *
 * The loop must be the one the PATH depends on. A registration inside a loop over
 * something else -- a list of middlewares, a set of ports -- is one route, and expanding
 * it over an unrelated collection would invent addresses.
 */
function loopExpansion(
  call: ts.CallExpression,
  consts: Map<string, ts.Expression>,
  resolveRegistry: RegistryResolver | undefined,
  registered: Set<string>,
): string[] | undefined {
  if (!resolveRegistry || call.arguments.length === 0) return undefined;
  const pathExpr = call.arguments[0];
  if (ts.isStringLiteralLike(pathExpr)) return undefined;

  for (let node: ts.Node | undefined = call.parent, hops = 0; node && hops < 32; node = node.parent, hops++) {
    if (!ts.isForOfStatement(node)) continue;
    const declarations = ts.isVariableDeclarationList(node.initializer)
      ? node.initializer.declarations
      : [];
    if (declarations.length !== 1 || !ts.isIdentifier(declarations[0].name)) continue;
    const variable = declarations[0].name.text;
    if (!mentions(pathExpr, variable)) continue;

    const collection = resolveRegistry(node.expression);
    if (!collection) return undefined;

    const paths: string[] = [];
    for (const name of collection.names) {
      const folded = foldLoopPath(pathExpr, consts, variable, collection.property, name);
      // All or nothing. A collection where one element folds and another does not is a
      // collection this did not actually understand, and a partial expansion would be
      // the worst of both: some addresses invented, the rest silently missing.
      if (folded === undefined) return undefined;
      paths.push(folded);
    }
    const fresh = paths.filter((path) => !registered.has(path));
    for (const path of paths) registered.add(path);
    return fresh;
  }
  return undefined;
}

/** Whether an expression reads a name. */
function mentions(expr: ts.Node, name: string): boolean {
  if (ts.isIdentifier(expr)) return expr.text === name;
  let found = false;
  ts.forEachChild(expr, (child) => {
    if (!found) found = mentions(child, name);
  });
  return found;
}

/** A path expression with the loop element's name substituted in. */
function foldLoopPath(
  expr: ts.Expression,
  consts: Map<string, ts.Expression>,
  variable: string,
  property: string,
  value: string,
): string | undefined {
  if (ts.isParenthesizedExpression(expr)) {
    return foldLoopPath(expr.expression, consts, variable, property, value);
  }
  if (property === "" && ts.isIdentifier(expr) && expr.text === variable) return value;
  if (
    property !== "" &&
    ts.isPropertyAccessExpression(expr) &&
    ts.isIdentifier(expr.expression) &&
    expr.expression.text === variable &&
    expr.name.text === property
  ) {
    return value;
  }
  if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = foldLoopPath(expr.left, consts, variable, property, value);
    const right = foldLoopPath(expr.right, consts, variable, property, value);
    return left === undefined || right === undefined ? undefined : left + right;
  }
  if (ts.isTemplateExpression(expr)) {
    let out = expr.head.text;
    for (const span of expr.templateSpans) {
      const part = foldLoopPath(span.expression, consts, variable, property, value);
      if (part === undefined) return undefined;
      out += part + span.literal.text;
    }
    return out;
  }
  // Anything else has to stand on its own -- a constant, a literal, a template of
  // constants -- and if it does not, this registration is not one whose address the
  // frontend can state per element.
  if (mentions(expr, variable)) return undefined;
  const text = pathText(expr, consts);
  return isUnresolvedPath(text) ? undefined : text;
}

function routesFrom(
  call: ts.CallExpression,
  method: string,
  prefix: string,
  chainPath: string | undefined,
  consts: Map<string, ts.Expression>,
  framework: string,
  loopPaths: string[] | undefined,
  resolveFunction: ResolveFunction,
  locOf: (node: ts.Node) => { file: string; line: number; column: number },
): EntryPoint[] {
  const args = call.arguments;
  // A verb call in a `.route(path)` chain carries no path of its own: its first argument
  // is already a handler. Everywhere else, a route method's first argument IS its path --
  // that is the framework's signature, and it holds whether or not the path is a literal.
  let routePath = chainPath ?? (args.length > 0 ? pathText(args[0], consts) : unresolvedPath());
  let start = chainPath === undefined && args.length > 0 ? 1 : 0;

  if (start === 1 && args.length > 1 && ts.isStringLiteralLike(args[1]) && args[1].text.startsWith("/")) {
    // Koa allows a route NAME in front of the path: `router.post("thing.create",
    // middleware, handler)`. The name is what the application calls the route and is
    // the only identifier it has, so it stands in for the path -- which is what ADR-009
    // asks for when the engine knows least.
    routePath = args[1].text;
    start = 2;
  }

  // The LAST argument is the handler; everything before it is middleware applied to this
  // route. It used to be the last argument this frontend could RESOLVE, which is a
  // different thing: `app.get("/metrics", apiAuth, prometheusAPIMetrics())` ends in a
  // factory call from a package outside the tree, so the search walked back past it and
  // anchored the route to its authentication middleware. The surface then said the
  // handler of /metrics was the auth check -- a false statement about the one function
  // every judgement about that route is made against.
  let handlerIndex = -1;
  for (let i = args.length - 1; i >= start; i--) {
    if (isHandlerArgument(args[i])) {
      handlerIndex = i;
      break;
    }
  }

  // A route whose handler cannot be resolved STILL EXISTS. `controller.register`
  // required through CommonJS often resolves to nothing, and dropping the route
  // there makes the enumerated surface silently incomplete — the one thing it must
  // never be (ADR-009). Emit it with no function: the operator sees the route, and
  // analyses that need a body skip it. What the handler was WRITTEN as is recorded
  // either way, so an unresolved one is a named gap rather than a blank.
  const handler = handlerIndex >= 0 ? resolveFunction(args[handlerIndex]) : undefined;
  const middleware = middlewareFrom(
    call,
    "route",
    resolveFunction,
    locOf,
    handlerIndex >= 0 ? handlerIndex : args.length,
  );

  // A configured prefix that defaults to empty leaves `app.get(`${baseUriPath}`)`
  // registering the empty string, and Express serves that at the root. Recording it as
  // "" would print a blank column where a path belongs.
  const written = !handler && handlerIndex >= 0
    ? args[handlerIndex].getText(args[handlerIndex].getSourceFile())
    : "";

  // One row per address. A loop over a static registry is a single call site serving
  // many addresses, and they share this handler because the handler dispatches on the
  // one they were reached at.
  const addresses = loopPaths ?? [routePath];
  return addresses.map((address) => {
    const detail: Record<string, string> = {
      method: method.toUpperCase(),
      path: joinRoute(prefix, address) || "/",
      module: locOf(call).file,
    };
    if (written) detail.handler = written;
    return {
      functionId: handler ? handler.id : "",
      kind: "http-route",
      framework,
      detail,
      loc: locOf(call),
      middleware,
    };
  });
}

/**
 * Whether this argument occupies a HANDLER slot rather than the path slot.
 *
 * Written as the negative of "could be a path" on purpose: a registration's first
 * argument is its path unless it plainly is not one, and everything from there on is a
 * function until the last, which is the handler.
 */
function isHandlerArgument(node: ts.Expression): boolean {
  if (ts.isStringLiteralLike(node) || ts.isTemplateExpression(node)) return false;
  if (ts.isRegularExpressionLiteral(node) || ts.isArrayLiteralExpression(node)) return false;
  return couldBeHandler(node);
}
