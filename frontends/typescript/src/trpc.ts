// tRPC framework model.
//
// A tRPC application registers nothing. There is no `app.post(path, handler)` anywhere in
// it: a procedure is a value built by a builder chain, and the addresses it answers at
// come from the KEY it is filed under in an object literal, composed with the keys of
// every router that object is nested inside. Nothing in the source spells the address out.
//
//     export const templateRouter = router({
//       createDocumentFromTemplate: authenticatedProcedure
//         .meta({ openapi: { method: 'POST', path: '/template/use' } })
//         .input(ZCreateDocumentFromTemplateRequestSchema)
//         .mutation(async ({ ctx, input }) => { ... }),
//     });
//
// So the Express model sees nothing, the file-route model sees nothing, and an
// application whose entire API is written this way enumerates as its handful of leftover
// REST endpoints. documenso lowered to 62 entry points over 274 procedures, and the scan's
// own completeness banner said 76 functions read caller input that no entry point reaches.
//
// Isolated in its own module for the same reason the Express model is: externalizing it
// into declarative data (ADR-004) should be a move rather than an untangling.

import ts from "typescript";
import type { EntryPoint, MiddlewareRef } from "./ir.ts";
import type { FuncRef, ResolveFunction } from "./express.ts";

/** How a procedure chain ENDS. The terminal call is what takes the handler. */
const TERMINALS = new Set(["query", "mutation", "subscription"]);

/**
 * Builder steps that make a chain a tRPC procedure rather than something else that
 * happens to own a method called `mutation`.
 *
 * The terminal name alone is not evidence: `useMutation`, a GraphQL client and half the
 * ORMs in existence have one. What is evidence is the BUILDER -- a chain that declares its
 * input schema, its metadata or a middleware before ending in a handler is the tRPC shape
 * and nothing else writes it.
 */
const BUILDER_STEPS = new Set(["input", "output", "meta", "use", "concat", "unstable_concat"]);

/** How a router is spelled. `t.router` is the raw builder; the rest are what apps re-export it as. */
const ROUTER_FACTORIES = new Set(["router", "createTRPCRouter", "createRouter", "mergeRouters"]);

/** A procedure and everything the source says about it. */
export interface Procedure {
  /** The terminal call: `.mutation(handler)`. */
  call: ts.CallExpression;
  /** "query" | "mutation" | "subscription". */
  verb: string;
  /** The identifier the builder chain is rooted at, e.g. `authenticatedProcedure`. */
  builder: string;
  /** Middleware named by `.use(...)` steps in the chain. */
  uses: ts.Expression[];
  /** The `openapi` metadata the chain declared, when it declared one. */
  rest?: { method: string; path: string };
  /** Where the procedure is written. */
  node: ts.Node;
}

/**
 * What the whole program says about its tRPC surface.
 *
 * Program-wide by necessity, and this is the sharpest case of it in the frontend: a
 * procedure's address is the concatenation of keys from files that never mention each
 * other. `appRouter` in `router.ts` files `templateRouter` under `template`;
 * `template-router/router.ts` files the procedure under `createDocumentFromTemplate`; and
 * `template-router/get-templates-by-ids.ts` exports a procedure that neither of them
 * defines. No single file can answer, which is the same shape ADR-001 already forces for
 * plugin prefixes and registration loops.
 */
export class TrpcProgram {
  private readonly procedures = new Map<ts.Node, Procedure>();
  private readonly routers = new Set<ts.ObjectLiteralExpression>();
  /** Object-literal or procedure nodes some router files under a key. */
  private readonly children = new Map<ts.Node, Array<[string, ts.Node]>>();
  private readonly referenced = new Set<ts.Node>();
  private paths = new Map<ts.Node, string>();
  private resolved = false;

  private readonly checker: ts.TypeChecker;

  constructor(checker: ts.TypeChecker) {
    this.checker = checker;
  }

  /** Reads one file's routers and procedures. Called for every source before any lowering. */
  collect(sf: ts.SourceFile): void {
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        const object = routerArgument(node);
        if (object) this.addRouter(object);
        const proc = procedureOf(node);
        if (proc) this.procedures.set(node, proc);
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }

  private addRouter(object: ts.ObjectLiteralExpression): void {
    if (this.routers.has(object)) return;
    this.routers.add(object);
    const edges: Array<[string, ts.Node]> = [];
    for (const prop of object.properties) {
      const key = propertyKey(prop);
      if (!key) continue;
      const value = propertyValue(prop);
      if (!value) continue;
      const target = this.targetOf(value, 0);
      if (!target) continue;
      edges.push([key, target]);
      this.referenced.add(target);
    }
    this.children.set(object, edges);
  }

  /**
   * The router object or procedure a property value stands for.
   *
   * Bounded and by symbol, which is what lets `template: templateRouter` reach an object
   * literal in another package. A value this cannot follow contributes no address, which
   * is the honest outcome: the procedure behind it still appears, under the name its own
   * file gives it.
   */
  private targetOf(expr: ts.Expression, depth: number): ts.Node | undefined {
    if (depth > 6) return undefined;
    if (ts.isCallExpression(expr)) {
      const object = routerArgument(expr);
      if (object) {
        this.addRouter(object);
        return object;
      }
      const proc = this.procedures.get(expr) ?? procedureOf(expr);
      if (proc) {
        this.procedures.set(expr, proc);
        return expr;
      }
    }
    if (ts.isObjectLiteralExpression(expr)) {
      // `router({ a: { b: proc } })` is not legal tRPC, but a plain nested object IS how
      // several applications group procedures before handing the group to `router`.
      this.addRouter(expr);
      return expr;
    }
    const named = ts.isPropertyAccessExpression(expr) ? expr.name : expr;
    if (!ts.isIdentifier(named)) return undefined;
    let sym = this.checker.getSymbolAtLocation(named);
    if (!sym) return undefined;
    if (sym.flags & ts.SymbolFlags.Alias) {
      try {
        sym = this.checker.getAliasedSymbol(sym);
      } catch {
        return undefined;
      }
    }
    for (const decl of sym.declarations ?? []) {
      if (ts.isVariableDeclaration(decl) && decl.initializer) {
        return this.targetOf(decl.initializer, depth + 1);
      }
      if (ts.isPropertyAssignment(decl)) {
        return this.targetOf(decl.initializer, depth + 1);
      }
    }
    return undefined;
  }

  /**
   * The dotted address of every procedure, walked down from the routers nobody nests.
   *
   * A router that is itself filed under a key contributes that key to everything below
   * it; a router nobody files is a root and contributes nothing. Where the composition
   * does not resolve -- a router built by a helper, a procedure exported for a file this
   * scan does not hold -- the procedure gets no dotted address rather than a guessed one.
   */
  private resolvePaths(): void {
    if (this.resolved) return;
    this.resolved = true;
    const seen = new Set<ts.Node>();
    const walk = (node: ts.Node, prefix: string): void => {
      if (seen.has(node)) return;
      seen.add(node);
      if (this.procedures.has(node)) {
        if (!this.paths.has(node)) this.paths.set(node, prefix);
        return;
      }
      for (const [key, child] of this.children.get(node) ?? []) {
        walk(child, prefix ? `${prefix}.${key}` : key);
      }
      seen.delete(node);
    };
    for (const object of this.routers) {
      if (!this.referenced.has(object)) walk(object, "");
    }
  }

  /** Every procedure this file declares, as entry points. */
  entryPoints(
    sf: ts.SourceFile,
    resolveFunction: ResolveFunction,
    locOf: (node: ts.Node) => { file: string; line: number; column: number },
  ): EntryPoint[] {
    this.resolvePaths();
    const out: EntryPoint[] = [];
    for (const [node, proc] of this.procedures) {
      if (node.getSourceFile() !== sf) continue;
      out.push(this.entryPoint(proc, resolveFunction, locOf));
    }
    // One row per procedure, in source order, so two runs over one file agree.
    out.sort((a, b) => (a.loc?.line ?? 0) - (b.loc?.line ?? 0) || (a.loc?.column ?? 0) - (b.loc?.column ?? 0));
    return out;
  }

  private entryPoint(
    proc: Procedure,
    resolveFunction: ResolveFunction,
    locOf: (node: ts.Node) => { file: string; line: number; column: number },
  ): EntryPoint {
    const handlerArg = proc.call.arguments[0];
    const handler: FuncRef | undefined = handlerArg ? resolveFunction(handlerArg) : undefined;
    const dotted = this.paths.get(proc.call);

    // The address, in the order the source states it most plainly. A procedure carrying
    // `openapi` metadata is served as REST at exactly the path written there -- that is
    // what the metadata IS -- and everything else is reached at its dotted procedure name,
    // which is the address tRPC's own HTTP adapter serves it at.
    const path = proc.rest?.path ?? dotted ?? "";
    const method = proc.rest?.method ?? (proc.verb === "query" ? "GET" : "POST");

    const middleware: MiddlewareRef[] = [];
    if (proc.builder) {
      // The builder IS the control. `authenticatedProcedure` and `procedure` differ by
      // exactly one middleware, and which one a procedure was built from is the whole of
      // what the source says about who may call it. Recorded as a route-scoped binding so
      // the population can compare siblings -- which is the only way to see that one
      // procedure in a router of twenty was built from the public one.
      const ref = resolveFunction(procedureRoot(proc.call));
      middleware.push({
        ...(ref ? { functionId: ref.id } : {}),
        symbol: proc.builder,
        name: proc.builder,
        scope: "route",
        loc: locOf(proc.node),
      });
    }
    for (const use of proc.uses) {
      const ref = resolveFunction(use);
      const name = ts.isIdentifier(use)
        ? use.text
        : ts.isPropertyAccessExpression(use)
          ? `${use.expression.getText(use.getSourceFile())}.${use.name.text}`
          : "";
      if (!name && !ref) continue;
      middleware.push({
        ...(ref ? { functionId: ref.id } : {}),
        ...(name ? { symbol: name, name } : {}),
        scope: "route",
        loc: locOf(use),
      });
    }

    // The ROUTER a procedure is filed under, which is the author-written boundary the core
    // compares peers across. Emphatically not the builder: `procedure` and
    // `authenticatedProcedure` differ by exactly the control the population is meant to
    // notice, so keying the group on the builder would put every unauthenticated procedure
    // in a population of its own and guarantee the comparison never happens.
    const router = dotted ? dotted.split(".").slice(0, -1).join(".") : "";
    const detail: Record<string, string> = {
      method,
      // A procedure whose address the composition did not resolve still EXISTS, and the
      // marker names what could not be read rather than claiming an address (ADR-009).
      path: path || `<unresolved:${proc.builder || "trpc procedure"}>`,
      module: locOf(proc.call).file,
      ...(router ? { mount: router } : {}),
    };
    if (dotted && proc.rest) detail.procedure = dotted;
    if (!handler && handlerArg) {
      detail.handler = handlerArg.getText(handlerArg.getSourceFile()).slice(0, 60);
    }
    return {
      functionId: handler ? handler.id : "",
      kind: "http-route",
      framework: "trpc",
      detail,
      loc: locOf(proc.node),
      middleware,
    };
  }
}

/** The object literal a router factory was handed, when this call is one. */
function routerArgument(call: ts.CallExpression): ts.ObjectLiteralExpression | undefined {
  const callee = call.expression;
  const name = ts.isPropertyAccessExpression(callee)
    ? callee.name.text
    : ts.isIdentifier(callee)
      ? callee.text
      : "";
  if (!ROUTER_FACTORIES.has(name)) return undefined;
  const first = call.arguments[0];
  return first && ts.isObjectLiteralExpression(first) ? first : undefined;
}

/** The procedure a terminal call describes, when the chain in front of it is a builder. */
function procedureOf(call: ts.CallExpression): Procedure | undefined {
  const callee = call.expression;
  if (!ts.isPropertyAccessExpression(callee)) return undefined;
  const verb = callee.name.text;
  if (!TERMINALS.has(verb)) return undefined;
  if (call.arguments.length !== 1) return undefined;
  if (!couldBeHandler(call.arguments[0])) return undefined;

  let builderSteps = 0;
  let root = "";
  let rest: { method: string; path: string } | undefined;
  const uses: ts.Expression[] = [];
  let cur: ts.Expression = callee.expression;
  for (let hops = 0; hops < 24; hops++) {
    if (ts.isCallExpression(cur)) {
      const inner = cur.expression;
      if (ts.isPropertyAccessExpression(inner)) {
        const step = inner.name.text;
        if (BUILDER_STEPS.has(step)) builderSteps++;
        if (step === "use") uses.push(...cur.arguments);
        if (step === "meta" && cur.arguments[0]) rest = rest ?? openApiMeta(cur.arguments[0]);
        cur = inner.expression;
        continue;
      }
      cur = inner;
      continue;
    }
    if (ts.isPropertyAccessExpression(cur)) {
      cur = cur.expression;
      continue;
    }
    if (ts.isIdentifier(cur)) root = cur.text;
    break;
  }

  // A chain with no builder step is only a procedure if the root SAYS it is one. Both
  // halves are needed: `t.procedure.query(fn)` declares nothing and is still tRPC, and
  // `db.user.mutation(fn)` -- which nobody writes, but the shape allows -- must not be.
  if (builderSteps === 0 && !/procedure$/i.test(root)) return undefined;
  return { call, verb, builder: root, uses, rest, node: call };
}

/** The identifier a procedure chain is rooted at, as a node the resolver can follow. */
function procedureRoot(call: ts.CallExpression): ts.Expression {
  let cur: ts.Expression = call.expression;
  for (let hops = 0; hops < 24; hops++) {
    if (ts.isCallExpression(cur)) {
      cur = cur.expression;
      continue;
    }
    if (ts.isPropertyAccessExpression(cur)) {
      cur = cur.expression;
      continue;
    }
    break;
  }
  return cur;
}

/**
 * The REST address `.meta({ openapi: { method, path } })` states.
 *
 * `enabled: false` is read and is decisive: the metadata is present so the schema
 * generator can skip it, and treating it as an address would put a route on the surface
 * that answers nothing -- the phantom-address failure ADR-009 is written against.
 */
function openApiMeta(expr: ts.Expression): { method: string; path: string } | undefined {
  if (!ts.isObjectLiteralExpression(expr)) return undefined;
  for (const prop of expr.properties) {
    if (!ts.isPropertyAssignment(prop) || propertyKey(prop) !== "openapi") continue;
    const spec = prop.initializer;
    if (!ts.isObjectLiteralExpression(spec)) continue;
    let method = "";
    let path = "";
    for (const field of spec.properties) {
      if (!ts.isPropertyAssignment(field)) continue;
      const key = propertyKey(field);
      if (key === "enabled" && field.initializer.kind === ts.SyntaxKind.FalseKeyword) {
        return undefined;
      }
      if (key === "method" && ts.isStringLiteralLike(field.initializer)) {
        method = field.initializer.text.toUpperCase();
      }
      if (key === "path" && ts.isStringLiteralLike(field.initializer)) {
        path = field.initializer.text;
      }
    }
    if (method && path) return { method, path };
  }
  return undefined;
}

function propertyKey(prop: ts.Node): string {
  if (ts.isPropertyAssignment(prop) || ts.isMethodDeclaration(prop)) {
    const name = prop.name;
    if (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) return name.text;
    return "";
  }
  if (ts.isShorthandPropertyAssignment(prop)) return prop.name.text;
  return "";
}

function propertyValue(prop: ts.ObjectLiteralElementLike): ts.Expression | undefined {
  if (ts.isPropertyAssignment(prop)) return prop.initializer;
  if (ts.isShorthandPropertyAssignment(prop)) return prop.name;
  return undefined;
}

/** A function, or a name that might hold one. */
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
