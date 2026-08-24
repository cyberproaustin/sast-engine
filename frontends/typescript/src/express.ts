// Express framework model.
//
// v0 encodes this as code because the declarative model format does not exist yet.
// It is deliberately isolated in its own module so that externalizing it (ADR-004)
// is a move rather than an untangling. Nothing in lower.ts knows Express exists.

import ts from "typescript";
import type { EntryPoint, MiddlewareRef } from "./ir.ts";

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
): EntryPoint[] {
  const expressNames = new Set<string>();
  const routerNames = new Set<string>();
  for (const [local, ref] of imports) {
    if (ref.module !== "express") continue;
    expressNames.add(local);
    // `const { Router } = require("express")` binds the factory directly.
    if (ref.export === "Router") routerNames.add(local);
  }
  // No early exit on an empty binding set: `require("express").Router()` names
  // express inline and produces no import binding at all, which is how a good deal
  // of CommonJS code is written.
  const appNames = collectAppBindings(sf, expressNames, routerNames);
  // Routers reach a module as a PARAMETER constantly — `module.exports = (app) =>
  // { app.get(...) }`. There is no binding to find, so recognize the shape instead:
  // a route-method call whose first argument is a path literal. This keys on
  // structure rather than on the receiver being named "app" (ADR-010).
  const shaped = collectRouterShapes(sf);
  for (const name of shaped) appNames.add(name);
  if (appNames.size === 0) return [];

  // Application-wide middleware. Path scoping and registration order are not modeled
  // yet, so this is attributed to every route on the same binding; that is why it is
  // recorded with scope "app" rather than merged into the route chain.
  const appMiddleware: MiddlewareRef[] = [];
  const entryPoints: EntryPoint[] = [];

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const target = node.expression.expression;
      const method = node.expression.name.text;
      if (ts.isIdentifier(target) && appNames.has(target.text)) {
        if (method === "use") {
          appMiddleware.push(...middlewareFrom(node, "app", resolveFunction, locOf));
        } else if (ROUTE_METHODS.has(method)) {
          entryPoints.push(...routesFrom(node, method, resolveFunction, locOf));
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
      ts.isCallExpression(node.initializer) &&
      isExpressFactory(node.initializer.expression, expressNames, routerNames)
    ) {
      bindings.add(node.name.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  return bindings;
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
      // A path literal is what distinguishes a route registration from `map.get(k)`
      // or `cache.delete(k)`.
      if (ts.isStringLiteralLike(first) && first.text.startsWith("/")) {
        out.add(node.expression.expression.text);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  return out;
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

function routesFrom(
  call: ts.CallExpression,
  method: string,
  resolveFunction: ResolveFunction,
  locOf: (node: ts.Node) => { file: string; line: number; column: number },
): EntryPoint[] {
  const args = call.arguments;
  let routePath = "*";
  let start = 0;

  if (args.length > 0 && ts.isStringLiteralLike(args[0])) {
    routePath = args[0].text;
    start = 1;
  }

  // The LAST function argument is the handler; everything before it is middleware
  // applied to this route. Treating every function argument as a handler both
  // invents entry points and loses the controls guarding the real one.
  let handlerIndex = -1;
  for (let i = args.length - 1; i >= start; i--) {
    if (resolveFunction(args[i])) {
      handlerIndex = i;
      break;
    }
  }

  // A route whose handler cannot be resolved STILL EXISTS. `controller.register`
  // required through CommonJS often resolves to nothing, and dropping the route
  // there makes the enumerated surface silently incomplete — the one thing it must
  // never be (ADR-009). Emit it with no function: the operator sees the route, and
  // analyses that need a body skip it.
  const handler = handlerIndex >= 0 ? resolveFunction(args[handlerIndex]) : undefined;
  const middleware = middlewareFrom(
    call,
    "route",
    resolveFunction,
    locOf,
    handlerIndex >= 0 ? handlerIndex : args.length,
  );

  return [
    {
      functionId: handler ? handler.id : "",
      kind: "http-route",
      framework: "express",
      detail: {
        method: method.toUpperCase(),
        path: routePath,
        module: locOf(call).file,
      },
      loc: locOf(call),
      middleware,
    },
  ];
}
