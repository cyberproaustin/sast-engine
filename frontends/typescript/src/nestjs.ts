// NestJS framework model.
//
// A different registration shape from Express: routes are declared by decorators on
// class methods rather than by calls on a router object, so none of the Express
// detection applies. Isolated in its own module for the same reason (ADR-004).
//
// The security-relevant parts are the same three questions: where does untrusted
// input enter, what guards the entry point, and what path is it served at.

import ts from "typescript";
import type { EntryPoint, MiddlewareRef } from "./ir.ts";
import type { FuncRef, ResolveFunction } from "./express.ts";

const ROUTE_DECORATORS = new Map<string, string>([
  ["Get", "GET"],
  ["Post", "POST"],
  ["Put", "PUT"],
  ["Patch", "PATCH"],
  ["Delete", "DELETE"],
  ["Options", "OPTIONS"],
  ["Head", "HEAD"],
  ["All", "ALL"],
]);

/**
 * Parameter decorators the framework itself defines. Their meaning is known whether or
 * not their definitions are in the scanned tree, so their absence is not an unknown.
 */
const FRAMEWORK_PARAM_DECORATORS = new Set([
  "Param",
  "Body",
  "Query",
  "Headers",
  "Ip",
  "HostParam",
  "Req",
  "Request",
  "Res",
  "Response",
  "Next",
  "Session",
  "UploadedFile",
  "UploadedFiles",
  "Inject",
]);

/** Decorators that mark a parameter as carrying caller-supplied data. */
export const UNTRUSTED_PARAM_DECORATORS = new Set([
  "Param",
  "Body",
  "Query",
  "Headers",
  "Ip",
  "HostParam",
]);

type LocOf = (node: ts.Node) => { file: string; line: number; column: number };

function decoratorsOf(node: ts.Node): readonly ts.Decorator[] {
  return ts.canHaveDecorators(node) ? (ts.getDecorators(node) ?? []) : [];
}

/** The decorator's name, whether or not it is called: `@Get` and `@Get('x')`. */
function decoratorName(dec: ts.Decorator): string | undefined {
  const expr = ts.isCallExpression(dec.expression) ? dec.expression.expression : dec.expression;
  return ts.isIdentifier(expr) ? expr.text : undefined;
}

function firstStringArg(dec: ts.Decorator): string | undefined {
  if (!ts.isCallExpression(dec.expression)) return undefined;
  const arg = dec.expression.arguments[0];
  return arg && ts.isStringLiteralLike(arg) ? arg.text : undefined;
}

/** `@UseGuards(AuthGuard, RolesGuard)` — the controls on a Nest entry point. */
function guardsFrom(node: ts.Node, scope: string, locOf: LocOf): MiddlewareRef[] {
  const out: MiddlewareRef[] = [];
  for (const dec of decoratorsOf(node)) {
    if (decoratorName(dec) !== "UseGuards" || !ts.isCallExpression(dec.expression)) continue;
    for (const arg of dec.expression.arguments) {
      const name = ts.isIdentifier(arg)
        ? arg.text
        : ts.isPropertyAccessExpression(arg)
          ? arg.name.text
          : undefined;
      if (name) out.push({ symbol: name, name, scope, loc: locOf(arg) });
    }
  }
  return out;
}

function joinPath(prefix: string, suffix: string): string {
  const a = prefix.replace(/\/+$/, "");
  const b = suffix.replace(/^\/+/, "");
  if (!a && !b) return "/";
  return `/${[a, b].filter(Boolean).join("/")}`;
}

/**
 * Finds NestJS controllers and returns each routed method as an HTTP entry point,
 * with its class-level and method-level guards as the middleware chain.
 */
export function detectNestRoutes(
  sf: ts.SourceFile,
  resolveFunction: ResolveFunction,
  locOf: LocOf,
  definedInTree: Set<string>,
): EntryPoint[] {
  const entryPoints: EntryPoint[] = [];

  const visit = (node: ts.Node): void => {
    if (ts.isClassDeclaration(node)) {
      const controller = decoratorsOf(node).find((d) => decoratorName(d) === "Controller");
      if (controller) {
        const prefix = firstStringArg(controller) ?? "";
        // Class-level guards apply to every route on the controller.
        const classGuards = guardsFrom(node, "app", locOf);

        for (const member of node.members) {
          if (!ts.isMethodDeclaration(member)) continue;
          for (const dec of decoratorsOf(member)) {
            const method = ROUTE_DECORATORS.get(decoratorName(dec) ?? "");
            if (!method) continue;

            const handler: FuncRef | undefined = resolveFunction(member);
            const unresolved = unresolvedParams(member, definedInTree);
            entryPoints.push({
              functionId: handler ? handler.id : "",
              kind: "http-route",
              framework: "nestjs",
              detail: {
                method,
                path: joinPath(prefix, firstStringArg(dec) ?? ""),
                module: locOf(member).file,
              },
              loc: locOf(member),
              middleware: [...classGuards, ...guardsFrom(member, "route", locOf)],
              unresolvedParams: unresolved.length ? unresolved : undefined,
            });
            break;
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  return entryPoints;
}

/**
 * Parameters that Nest binds from the request. Unlike Express, untrusted input does
 * not arrive as a property of a `req` object — it is injected directly, so the
 * parameter itself is the source.
 */
export function untrustedParams(node: ts.SignatureDeclaration): Set<number> {
  const out = new Set<number>();
  node.parameters.forEach((param, index) => {
    for (const dec of decoratorsOf(param)) {
      const name = decoratorName(dec);
      if (name && UNTRUSTED_PARAM_DECORATORS.has(name)) out.add(index);
    }
  });
  return out;
}

/**
 * Properties that belong to the HTTP request itself.
 *
 * Listed the other way round on purpose. A list of names that mean identity — user,
 * session, principal — is open-ended and unprincipled: it works until an application
 * calls its tenant a workspace, and then a correctly scoped query reads as unscoped.
 * This list is closed, because it is defined by the protocol and the framework rather
 * than by what any team named things.
 *
 * The inference it supports: a decorator that reads a property NOT in this list is
 * reading something server-side code attached to the request — a guard, a middleware,
 * an auth layer. Whatever it is, the caller did not choose it, and that is the property
 * that makes a selection constrained rather than caller-controlled.
 */
const HTTP_REQUEST_PROPERTIES = new Set([
  "body",
  "query",
  "params",
  "headers",
  "cookies",
  "signedCookies",
  "url",
  "originalUrl",
  "baseUrl",
  "path",
  "method",
  "protocol",
  "hostname",
  "host",
  "ip",
  "ips",
  "files",
  "file",
  "rawBody",
  "socket",
  "get",
  "header",
]);

function isRequestLike(expr: ts.Expression): boolean {
  // `req`, `request`, `ctx.switchToHttp().getRequest()`, and locals assigned from them
  // all end in a name or call that says so.
  if (ts.isIdentifier(expr)) return /^(req|request)/i.test(expr.text);
  if (ts.isCallExpression(expr) && ts.isPropertyAccessExpression(expr.expression)) {
    return /^get(Request|Context|Args)$/.test(expr.expression.name.text);
  }
  if (ts.isElementAccessExpression(expr)) return isRequestLike(expr.expression);
  if (ts.isPropertyAccessExpression(expr)) return /^(req|request)$/i.test(expr.name.text);
  return false;
}

/**
 * Finds custom parameter decorators that hand the handler something the caller did not
 * choose — which, for every judgement about who owns a record, is the fact that matters.
 *
 * NestJS applications almost never spell identity as `req.user` in a handler. They
 * define a decorator — `@UserSession()`, `@AuthWorkspace()`, whatever the team called it
 * — and inject it. A model that only knows `req.user` observes no identity anywhere in
 * such an application, and then reports every correctly scoped query as unowned.
 *
 * The name is not the evidence and no list of likely names appears here. A custom
 * decorator is built by `createParamDecorator(factory)`, and the factory's whole job is
 * to pull one thing off the request — so the decorator states what it carries in its own
 * definition, and this reads it.
 *
 * What it looks for is deliberately the complement of what you might expect. Rather than
 * ask whether the factory reads a property that sounds like identity, it asks whether the
 * property is part of the HTTP request at all. `body`, `query`, `headers` and the rest
 * came from the caller. Anything else on that object was put there by server-side code —
 * a guard, a middleware, an auth layer — and the caller could not have chosen it.
 *
 * That inversion is what makes the rule hold up. A list of identity-sounding names works
 * until an application calls its tenant a `workspace`, and one production codebase in the
 * validation set does exactly that: six correctly scoped operations read as unowned until
 * this asked the question the other way round.
 */
export function identityDecorators(sf: ts.SourceFile): Set<string> {
  const found = new Set<string>();

  const readsServerContext = (factory: ts.Node): boolean => {
    let hit = false;
    const scan = (n: ts.Node): void => {
      if (hit) return;
      if (ts.isPropertyAccessExpression(n) && !HTTP_REQUEST_PROPERTIES.has(n.name.text)) {
        // Only a read off something that is plainly the request. `ctx.getType()` and
        // `GqlExecutionContext.create(context)` are plumbing, not request data.
        if (isRequestLike(n.expression)) {
          hit = true;
          return;
        }
      }
      ts.forEachChild(n, scan);
    };
    scan(factory);
    return hit;
  };

  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const init = node.initializer;
      if (
        ts.isCallExpression(init) &&
        ts.isIdentifier(init.expression) &&
        init.expression.text === "createParamDecorator" &&
        init.arguments[0] &&
        readsServerContext(init.arguments[0])
      ) {
        found.add(node.name.text);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  return found;
}

/** Parameters injected by a decorator that was shown to carry the caller's identity. */
export function identityParams(node: ts.SignatureDeclaration, identity: Set<string>): Set<number> {
  const out = new Set<number>();
  if (identity.size === 0) return out;
  node.parameters.forEach((param, index) => {
    for (const dec of decoratorsOf(param)) {
      const name = decoratorName(dec);
      if (name && identity.has(name)) out.add(index);
    }
  });
  return out;
}

/** Every name defined in this file by `createParamDecorator`, identity-carrying or not. */
export function definedParamDecorators(sf: ts.SourceFile): Set<string> {
  const found = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      ts.isCallExpression(node.initializer) &&
      ts.isIdentifier(node.initializer.expression) &&
      node.initializer.expression.text === "createParamDecorator"
    ) {
      found.add(node.name.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

/**
 * Parameter decorators applied to this handler whose definition is nowhere in the
 * scanned tree.
 *
 * Not an error and not a finding — a statement about the scan. A decorator the
 * framework defines is known by name; one the application defines is known by reading
 * its definition; one that is neither is an input of unknown meaning, and the honest
 * thing to do is say which one and let the operator widen the root.
 */
export function unresolvedParams(
  node: ts.SignatureDeclaration,
  definedInTree: Set<string>,
): string[] {
  const out: string[] = [];
  for (const param of node.parameters) {
    for (const dec of decoratorsOf(param)) {
      const name = decoratorName(dec);
      if (!name || FRAMEWORK_PARAM_DECORATORS.has(name) || definedInTree.has(name)) continue;
      if (!out.includes(name)) out.push(name);
    }
  }
  return out;
}
