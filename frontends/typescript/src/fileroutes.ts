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

import * as ts from "typescript";

import type { EntryPoint } from "./ir.ts";

/** Just enough of the resolver's answer to name the function. */
interface Resolved {
  id: string;
}

/** Files whose exports ARE the handlers. */
const ROUTE_FILES = new Set(["route", "+server", "server", "handler"]);

const VERBS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ALL"]);

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
 */
export function detectDescribedRoutes(
  sf: ts.SourceFile,
  resolveFunction: (node: ts.Node) => Resolved | undefined,
  locOf: (node: ts.Node) => { file: string; line: number; column: number },
): EntryPoint[] {
  const out: EntryPoint[] = [];

  const visit = (node: ts.Node): void => {
    if (ts.isObjectLiteralExpression(node)) {
      let verb = "";
      let routePath = "";
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
          ts.isPropertyAssignment(prop) &&
          ts.isStringLiteralLike(value)
        ) {
          routePath = value.text;
        } else if (key === "handler" || key === "handle" || key === "resolve") {
          handler = resolveFunction(value);
        }
      }
      if (verb && routePath && handler) {
        out.push({
          functionId: handler.id,
          kind: "http-route",
          framework: "described-route",
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

export function detectFileRoutes(
  sf: ts.SourceFile,
  moduleId: string,
  resolveFunction: (node: ts.Node) => Resolved | undefined,
  locOf: (node: ts.Node) => { file: string; line: number; column: number },
): EntryPoint[] {
  const parts = moduleId.split("/");
  const base = (parts.pop() ?? "").replace(/\.[cm]?[jt]sx?$/, "");
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
