// Routes that are not registered by calling a router.
//
// Three shapes, and each of them left an application's surface almost entirely empty.
//
// Next.js, Remix, Nuxt, SvelteKit and Medusa all register handlers this way: a file at a
// known name exports a function per HTTP verb, and the directory it sits in is the path.
// There is no registration to find -- which is why a frontend that looked only for calls
// enumerated ONE route of an application with 486, and reported a complete-looking
// surface while it did so.
//
// The path is derived from the directory, which is the only identifier available and is
// what the framework itself uses. `[id]` is a parameter and `(group)` is an organisational
// folder that does not appear in the URL; both are conventions these frameworks share.
//
// Next.js's older Pages Router is the same idea with the verb left out: one default export
// serves EVERY method and sorts them out itself, so the file names a path and nothing
// else. It is still the more common of the two routers, and an application built on it
// enumerated ZERO entry points against 54 handlers -- 56,824 lines that produced four
// findings, because a surface with nothing on it makes everything behind it unreachable.

import * as ts from "typescript";

import type { EntryPoint } from "./ir.ts";
import { collectStringBindings, pathText } from "./routepath.ts";

/** Just enough of the resolver's answer to name the function -- and to read it. */
interface Resolved {
  id: string;
  /** The declaration, when the resolver found one. A handler that dispatches on the
   * request method answers that question in its BODY, and this is the way in. */
  node?: ts.Node;
}

/** Files whose exports ARE the handlers. */
const ROUTE_FILES = new Set(["route", "+server", "server", "handler"]);

// Ordered, because a handler that dispatches on the method yields a SET of verbs and the
// order they happen to appear in its body is not a fact about the route.
const VERB_ORDER = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ALL"];

const VERBS = new Set(VERB_ORDER);

/** `===`, `!==` and their loose twins: every way a body asks which verb it was given. */
const EQUALITY = new Set([
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
]);

/**
 * A call that carries a VERB, a PATH and a HANDLER, whatever it is called.
 *
 * `setupApiRoute(router, "get", "/count", middlewares, handler)` and `this.route("GET",
 * "/aggregate/:className", middleware, handler)` are registrations by any reasonable
 * reading, and neither is a method on a router. Recognising the shape rather than the
 * name is the same decision the Express detector already makes for a router that arrives
 * as a parameter (ADR-010) -- and the alternative was 76 of one application's 553 routes
 * and 5 of another's 90.
 *
 * Held to a strict standard because the callee proves nothing: an argument must be an
 * exact HTTP verb, another must be a path, and the last must resolve to a function.
 */
export function detectHelperRoutes(
  sf: ts.SourceFile,
  resolveFunction: (node: ts.Node) => Resolved | undefined,
  locOf: (node: ts.Node) => { file: string; line: number; column: number },
): EntryPoint[] {
  const out: EntryPoint[] = [];

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && node.arguments.length >= 3) {
      const args = node.arguments;
      let verb = "";
      let routePath = "";
      for (const a of args) {
        if (!ts.isStringLiteralLike(a)) continue;
        if (!verb && VERBS.has(a.text.toUpperCase())) verb = a.text.toUpperCase();
        else if (!routePath && a.text.startsWith("/")) routePath = a.text;
      }
      const handler = verb && routePath ? resolveFunction(args[args.length - 1]) : undefined;
      if (handler) {
        out.push({
          functionId: handler.id,
          kind: "http-route",
          framework: "helper-route",
          detail: { method: verb === "ALL" ? "ANY" : verb, path: routePath },
          loc: locOf(node),
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

/**
 * A route DESCRIBED rather than registered: `{ method: "get", path: "/access", handler }`.
 *
 * Two frameworks in the clean corpus build their surface out of tables like this and
 * neither had a single entry point enumerated. The object says everything a route needs
 * to say; nothing calls anything until the framework walks the table at startup.
 *
 * The PATH is read the way every other registrar in this frontend reads one, and the
 * reason is measured: requiring a string literal here matched 109 of one application's
 * 208 descriptions -- 52%, which reads as coverage rather than as a sample. The other 99
 * are not a different shape. 39 are `path: ''`, the router's own mount point, which was
 * being rejected by a truthiness test rather than by anything about routes; 39 name a
 * constant declared at the top of the same file (`path: PATH_ENV`); 21 build one from a
 * constant (`` path: `${PATH_ENV}/off` ``). `pathText` already resolves all three for
 * Express, NestJS and the file routers, so the fix is to ask it rather than to teach this
 * function about constants.
 *
 * A path that genuinely cannot be read still yields a route, carrying the `<unresolved:>`
 * marker: a route exists at an address whether or not this frontend can spell it, and the
 * handler is what has to resolve for the description to be a registration at all.
 */
export function detectDescribedRoutes(
  sf: ts.SourceFile,
  resolveFunction: (node: ts.Node) => Resolved | undefined,
  locOf: (node: ts.Node) => { file: string; line: number; column: number },
): EntryPoint[] {
  const out: EntryPoint[] = [];
  // Collected once for the file, and only when the file holds a description at all:
  // this walks every declaration, and the detector runs over every object literal in
  // every module of the program.
  let consts: Map<string, ts.Expression> | undefined;

  const visit = (node: ts.Node): void => {
    if (ts.isObjectLiteralExpression(node)) {
      let verb = "";
      let routePath: string | undefined;
      let handler: Resolved | undefined;
      for (const prop of node.properties) {
        const key =
          ts.isPropertyAssignment(prop) || ts.isShorthandPropertyAssignment(prop)
            ? prop.name.getText(sf)
            : "";
        const value = ts.isPropertyAssignment(prop) ? prop.initializer : prop;
        if (key === "method" && ts.isPropertyAssignment(prop) && ts.isStringLiteralLike(value)) {
          if (VERBS.has(value.text.toUpperCase())) verb = value.text.toUpperCase();
        } else if (
          (key === "path" || key === "pathWithoutApiBasePath") &&
          ts.isPropertyAssignment(prop)
        ) {
          if (!consts) consts = collectStringBindings(sf);
          routePath = pathText(value, consts);
        } else if (key === "handler" || key === "handle" || key === "resolve") {
          handler = resolveFunction(value);
        }
      }
      if (verb && routePath !== undefined && handler) {
        out.push({
          functionId: handler.id,
          kind: "http-route",
          framework: "described-route",
          // `path: ''` is the router's own mount point and Express answers it there,
          // exactly as it answers `app.get(`${baseUriPath}`)` at the root when the
          // prefix is unset. Printing "" would leave a blank where an address belongs.
          detail: { method: verb === "ALL" ? "ANY" : verb, path: routePath || "/" },
          loc: locOf(node),
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

/** What a wrapper does with its own parameters when it forwards them to a registrar. */
interface Forwarded {
  verb: string;
  pathIndex: number;
  handlerIndex: number;
}

/**
 * A registration reached through a base class's own shorthand: `this.get(path, handler)`.
 *
 * The frameworks are recognised; this spelling was not. One application declares nine
 * routes this way and every one was missing from its surface, including the
 * unauthenticated `/internal-backstage/prometheus` endpoint -- a real finding that nothing
 * downstream could reach, because the route it lives on did not exist.
 *
 * It is a FORWARDING CHAIN rather than a new framework, and the whole chain is in the
 * tree: `Controller.get(path, handler, permission)` has one statement, `this.route({
 * method: 'get', path, handler, permission })`, and that shape is already modelled one
 * function above. So the wrapper is asked to prove itself -- its body must build exactly
 * one route description whose `path` and `handler` are its OWN parameters -- and the
 * verb comes from the literal the wrapper wrote, not from what the call site happened to
 * be called. Nothing here keys on the name `Controller`, on `route`, or on a package
 * (ADR-010): a wrapper that forwards to a registration IS a registration.
 */
export function detectForwardedRoutes(
  sf: ts.SourceFile,
  resolveFunction: (node: ts.Node) => Resolved | undefined,
  locOf: (node: ts.Node) => { file: string; line: number; column: number },
): EntryPoint[] {
  const out: EntryPoint[] = [];
  let consts: Map<string, ts.Expression> | undefined;

  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      VERBS.has(node.expression.name.text.toUpperCase()) &&
      node.arguments.length >= 2
    ) {
      // Resolution is what costs here, so the cheap tests come first: a verb for a
      // method name and two arguments. `map.get(k)` and `res.headers.get(name)` are out
      // before anything is looked up.
      const wrapper = resolveFunction(node.expression);
      const forwarded = wrapper?.node ? forwardedRegistration(wrapper.node, sf) : undefined;
      if (forwarded && forwarded.pathIndex < node.arguments.length && forwarded.handlerIndex < node.arguments.length) {
        const handler = resolveFunction(node.arguments[forwarded.handlerIndex]);
        if (handler) {
          if (!consts) consts = collectStringBindings(sf);
          const routePath = pathText(node.arguments[forwarded.pathIndex], consts);
          out.push({
            functionId: handler.id,
            kind: "http-route",
            framework: "described-route",
            detail: {
              method: forwarded.verb === "ALL" ? "ANY" : forwarded.verb,
              path: routePath || "/",
            },
            loc: locOf(node),
          });
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

/**
 * The one route description a wrapper builds out of its own parameters, or nothing.
 *
 * Exactly one, for the same reason the function resolver insists on a single returned
 * function: a wrapper that describes two routes is doing something this cannot state,
 * and picking one of them would be a guess.
 */
function forwardedRegistration(decl: ts.Node, sf: ts.SourceFile): Forwarded | undefined {
  if (!ts.isFunctionLike(decl)) return undefined;
  const body = (decl as ts.FunctionLikeDeclaration).body;
  if (!body) return undefined;

  const paramIndex = new Map<string, number>();
  decl.parameters.forEach((param, i) => {
    if (ts.isIdentifier(param.name)) paramIndex.set(param.name.text, i);
  });
  if (paramIndex.size === 0) return undefined;

  let found: Forwarded | undefined;
  let count = 0;
  const scan = (node: ts.Node): void => {
    if (ts.isObjectLiteralExpression(node)) {
      let verb = "";
      let pathIndex = -1;
      let handlerIndex = -1;
      for (const prop of node.properties) {
        if (!ts.isPropertyAssignment(prop) && !ts.isShorthandPropertyAssignment(prop)) continue;
        const key = prop.name.getText(prop.getSourceFile() ?? sf);
        const value: ts.Expression = ts.isPropertyAssignment(prop) ? prop.initializer : prop.name;
        if (key === "method" && ts.isStringLiteralLike(value) && VERBS.has(value.text.toUpperCase())) {
          verb = value.text.toUpperCase();
        } else if (key === "path" && ts.isIdentifier(value)) {
          pathIndex = paramIndex.get(value.text) ?? -1;
        } else if ((key === "handler" || key === "handle") && ts.isIdentifier(value)) {
          handlerIndex = paramIndex.get(value.text) ?? -1;
        }
      }
      if (verb && pathIndex >= 0 && handlerIndex >= 0) {
        count++;
        found = { verb, pathIndex, handlerIndex };
      }
    }
    ts.forEachChild(node, scan);
  };
  scan(body);

  return count === 1 ? found : undefined;
}

export function detectFileRoutes(
  sf: ts.SourceFile,
  moduleId: string,
  resolveFunction: (node: ts.Node) => Resolved | undefined,
  locOf: (node: ts.Node) => { file: string; line: number; column: number },
): EntryPoint[] {
  const parts = moduleId.split("/");
  const base = (parts.pop() ?? "").replace(/\.[cm]?[jt]sx?$/, "");

  const api = pagesApiAt(parts);
  if (api >= 0) return pagesRouterRoutes(sf, moduleId, parts.slice(api), base, resolveFunction, locOf);

  if (!ROUTE_FILES.has(base)) return [];

  const path = routePath(parts);
  const out: EntryPoint[] = [];

  const consider = (name: string, node: ts.Node): void => {
    if (!VERBS.has(name)) return;
    const handler = resolveFunction(node);
    out.push({
      functionId: handler ? handler.id : "",
      kind: "http-route",
      framework: "file-route",
      detail: {
        method: name === "ALL" ? "ANY" : name,
        path,
        module: moduleId,
      },
      loc: locOf(node),
    });
  };

  for (const stmt of sf.statements) {
    if (!isExported(stmt)) continue;
    if (ts.isFunctionDeclaration(stmt) && stmt.name) {
      consider(stmt.name.text, stmt);
      continue;
    }
    if (ts.isVariableStatement(stmt)) {
      for (const decl of stmt.declarationList.declarations) {
        if (ts.isIdentifier(decl.name) && decl.initializer) {
          consider(decl.name.text, decl.initializer);
        }
      }
    }
  }
  return out;
}

function isExported(stmt: ts.Statement): boolean {
  return (ts.getCombinedModifierFlags(stmt as ts.Declaration) & ts.ModifierFlags.Export) !== 0;
}

/**
 * Where `pages/api` begins, or -1.
 *
 * The suffix and not the position: `pages/api` sits under `apps/web/` in the application
 * this was written for and under `packages/*` in the next one, and a rule anchored at the
 * repository root finds neither. Returns the index of `api`, which is the first segment
 * of every URL this router serves.
 *
 * `pages/` NEXT DOOR is the other half of the same convention and is not a surface at all
 * -- 38 React components in that one application, every one of them a default-exported
 * function. Enumerating those would not be a slightly noisier surface; it would be a
 * surface made mostly of things a caller cannot reach, and ADR-009 makes the enumeration
 * the thing every finding rests on.
 */
function pagesApiAt(dirs: string[]): number {
  for (let i = dirs.length - 2; i >= 0; i--) {
    if (dirs[i] === "pages" && dirs[i + 1] === "api") return i + 1;
  }
  return -1;
}

/**
 * A Pages Router handler: one default export, every verb, path from the file.
 *
 * The file names no verb, so the verb has to come from the body. A handler that branches
 * on `req.method` is several handlers sharing a signature -- 70 such branches across 54
 * files in one application, and reporting them as one route each would say a caller
 * reaches `POST /api/links` through the same code that answers `GET`, which is the
 * question an ownership or authorization judgement is asking. One that does not branch
 * really does answer everything, and ANY is the honest word for that.
 *
 * The default export is the whole test. Next.js requires it to be the handler, so the
 * directory is the evidence and resolving it only names the function -- a route whose
 * handler arrives through a wrapper this cannot follow is still a route, exactly as it is
 * for the App Router above.
 */
function pagesRouterRoutes(
  sf: ts.SourceFile,
  moduleId: string,
  dirs: string[],
  base: string,
  resolveFunction: (node: ts.Node) => Resolved | undefined,
  locOf: (node: ts.Node) => { file: string; line: number; column: number },
): EntryPoint[] {
  const exported = defaultExport(sf);
  if (!exported) return [];

  const handler = resolveFunction(exported);
  // `index` is the directory itself, the one convention the two routers do not share:
  // here the LAST segment is a file rather than a folder, and it is the file that names
  // the parameter in `[id].ts`.
  const path = routePath(base === "index" ? dirs : [...dirs, base]);
  const verbs = dispatchedVerbs(handler?.node ?? exported);

  return (verbs.length > 0 ? verbs : ["ANY"]).map((method) => ({
    functionId: handler ? handler.id : "",
    kind: "http-route",
    framework: "next-pages",
    detail: { method, path, module: moduleId },
    loc: locOf(exported),
  }));
}

/** `export default function handler() {}` or `export default handler`. */
function defaultExport(sf: ts.SourceFile): ts.Node | undefined {
  for (const stmt of sf.statements) {
    if (ts.isExportAssignment(stmt) && !stmt.isExportEquals) return stmt.expression;
    if (!ts.isFunctionDeclaration(stmt)) continue;
    if ((ts.getCombinedModifierFlags(stmt) & ts.ModifierFlags.Default) !== 0) return stmt;
  }
  return undefined;
}

/**
 * The verbs a handler decides between, read off its own branches.
 *
 * Tied to the request PARAMETER rather than to the name `req`: the branch is only about
 * this route if it tests the argument this route was handed.
 *
 * `req.method !== "POST"` names POST for the same reason `=== "POST"` does. It is the
 * 405 guard -- `if (req.method !== "POST") return res.status(405)` -- which says the
 * handler serves that verb and refuses the rest, and it is how 10 of one application's
 * single-verb routes are written.
 */
function dispatchedVerbs(handler: ts.Node): string[] {
  if (!ts.isFunctionLike(handler)) return [];
  const req = handler.parameters[0]?.name;
  if (!req || !ts.isIdentifier(req)) return [];

  const found = new Set<string>();
  const isMethodOfRequest = (node: ts.Node): boolean =>
    ts.isPropertyAccessExpression(node) &&
    node.name.text === "method" &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === req.text;
  const take = (node: ts.Node): void => {
    if (ts.isStringLiteralLike(node) && VERBS.has(node.text.toUpperCase())) {
      found.add(node.text.toUpperCase());
    }
  };

  const visit = (node: ts.Node): void => {
    if (ts.isBinaryExpression(node) && EQUALITY.has(node.operatorToken.kind)) {
      if (isMethodOfRequest(node.left)) take(node.right);
      else if (isMethodOfRequest(node.right)) take(node.left);
    } else if (ts.isSwitchStatement(node) && isMethodOfRequest(node.expression)) {
      for (const clause of node.caseBlock.clauses) {
        if (ts.isCaseClause(clause)) take(clause.expression);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(handler);

  return VERB_ORDER.filter((verb) => found.has(verb));
}

/**
 * The URL a directory stands for.
 *
 * `[id]` is a parameter and `(group)` is an organisational folder the URL never sees --
 * conventions Next.js, Remix and Nuxt share. A leading `src` or `app` is the project's
 * own layout rather than part of any path.
 */
function routePath(dirs: string[]): string {
  const segments: string[] = [];
  for (const raw of dirs) {
    if (segments.length === 0 && (raw === "src" || raw === "app" || raw === "pages")) continue;
    if (raw.startsWith("(") && raw.endsWith(")")) continue;
    const rest = /^\[\[?\.\.\.(.+?)\]?\]$/.exec(raw);
    if (rest) {
      segments.push("*");
      continue;
    }
    const param = /^\[(.+)\]$/.exec(raw);
    segments.push(param ? `:${param[1]}` : raw);
  }
  return "/" + segments.join("/");
}
