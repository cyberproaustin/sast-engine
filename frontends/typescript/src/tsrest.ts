// ts-rest framework model.
//
// A ts-rest application splits a route in half and puts the halves in different files. The
// CONTRACT states the method and the path and holds no code:
//
//     export const ApiContractV1 = c.router({
//       getDocuments: { method: 'GET', path: '/api/v1/documents', ... },
//     });
//
// and the IMPLEMENTATION states the code and holds no address:
//
//     export const ApiContractV1Implementation = tsr.router(ApiContractV1, {
//       getDocuments: authenticatedMiddleware(async (args, user, team) => { ... }),
//     });
//
// Neither half is a route on its own, and neither file mentions the other's contents. The
// registration is the KEY they share, which is a fact about the program rather than about
// either file -- the same reason the tRPC model and the Django URLconf model are both
// program-wide (ADR-001).
//
// What the contract carries is unusually good evidence: the method and the path are string
// literals written by hand, and the path is absolute. There is no mount to resolve and
// nothing to guess.

import ts from "typescript";
import type { EntryPoint, MiddlewareRef } from "./ir.ts";
import type { ResolveFunction } from "./express.ts";

/** How a contract is built. `initContract()` returns an object whose `router` takes the table. */
const CONTRACT_FACTORIES = new Set(["router"]);

/** One entry of a contract: a method, a path, and the key both halves share. */
interface Route {
  method: string;
  path: string;
}

/** A contract table, by the key each route is filed under. */
type Contract = Map<string, Route>;

export class TsRestProgram {
  /** Contract object literals, and what each key says. */
  private readonly contracts = new Map<ts.Node, Contract>();
  // Implementation tables, holding the contract expression AS WRITTEN. Resolving it here
  // would depend on file order -- an implementation read before its contract would find
  // nothing -- so the join is deferred to `entryPoints`, which runs after every file.
  private readonly implementations: Array<{ table: ts.ObjectLiteralExpression; contract: ts.Expression }> = [];

  private readonly checker: ts.TypeChecker;

  constructor(checker: ts.TypeChecker) {
    this.checker = checker;
  }

  collect(sf: ts.SourceFile): void {
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        this.readContract(node);
        this.readImplementation(node);
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }

  /**
   * `c.router({ key: { method, path } })` -- a table whose values are route DESCRIPTIONS.
   *
   * Recognised by what the values are rather than by what the receiver is called: a
   * contract entry is an object literal carrying a string `method` and a string `path`,
   * and nothing else in either ecosystem is written that way. Requiring the whole table
   * to be routes would lose a contract that nests a sub-contract under a key, so the test
   * is per entry and a table with at least one route is a contract.
   */
  private readContract(call: ts.CallExpression): void {
    const callee = call.expression;
    const name = ts.isPropertyAccessExpression(callee) ? callee.name.text : "";
    if (!CONTRACT_FACTORIES.has(name)) return;
    const table = call.arguments[0];
    if (!table || !ts.isObjectLiteralExpression(table)) return;

    const routes: Contract = new Map();
    for (const prop of table.properties) {
      if (!ts.isPropertyAssignment(prop)) continue;
      const key = propertyKey(prop);
      const route = routeOf(prop.initializer);
      if (key && route) routes.set(key, route);
    }
    if (routes.size > 0) this.contracts.set(table, routes);
  }

  /** `tsr.router(Contract, { key: handler })` -- the halves, named together for once. */
  private readImplementation(call: ts.CallExpression): void {
    const callee = call.expression;
    const name = ts.isPropertyAccessExpression(callee) ? callee.name.text : "";
    if (name !== "router" || call.arguments.length < 2) return;
    const table = call.arguments[1];
    if (!table || !ts.isObjectLiteralExpression(table)) return;
    this.implementations.push({ table, contract: call.arguments[0] });
  }

  /** The contract table an identifier stands for, followed across files by symbol. */
  private contractNode(expr: ts.Expression, depth: number): ts.Node | undefined {
    if (depth > 6) return undefined;
    if (ts.isCallExpression(expr)) {
      const table = expr.arguments[0];
      if (table && this.contracts.has(table)) return table;
      return undefined;
    }
    if (ts.isObjectLiteralExpression(expr) && this.contracts.has(expr)) return expr;
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
        return this.contractNode(decl.initializer, depth + 1);
      }
    }
    return undefined;
  }

  /** Every route this file implements, joined to the address its contract states. */
  entryPoints(
    sf: ts.SourceFile,
    resolveFunction: ResolveFunction,
    locOf: (node: ts.Node) => { file: string; line: number; column: number },
  ): EntryPoint[] {
    const out: EntryPoint[] = [];
    for (const { table, contract } of this.implementations) {
      if (table.getSourceFile() !== sf) continue;
      const node = this.contractNode(contract, 0);
      const routes = node ? this.contracts.get(node) : undefined;
      if (!routes) continue;
      for (const prop of table.properties) {
        const key = propertyKey(prop);
        const route = key ? routes.get(key) : undefined;
        if (!route) continue;
        const value = ts.isPropertyAssignment(prop)
          ? prop.initializer
          : ts.isMethodDeclaration(prop)
            ? prop
            : undefined;
        if (!value) continue;

        // A handler wrapped in a middleware factory -- `authenticatedMiddleware(async
        // (...) => {})` -- is the ordinary shape here, and the wrapper is the control.
        // The resolver already follows a factory to the function it returns, so the
        // handler resolves; what the wrapper is CALLED is recorded beside it, because
        // that name is the whole of what the source says about who may reach this route.
        const middleware: MiddlewareRef[] = [];
        if (ts.isCallExpression(value) && ts.isIdentifier(value.expression)) {
          middleware.push({
            symbol: value.expression.text,
            name: value.expression.text,
            scope: "route",
            loc: locOf(value.expression),
          });
        }

        const handler = resolveFunction(value);
        out.push({
          functionId: handler ? handler.id : "",
          kind: "http-route",
          framework: "ts-rest",
          detail: {
            method: route.method.toUpperCase(),
            path: route.path,
            module: locOf(value).file,
            mount: key,
          },
          loc: locOf(value),
          middleware,
        });
      }
    }
    out.sort((a, b) => (a.loc?.line ?? 0) - (b.loc?.line ?? 0));
    return out;
  }
}

/** A contract entry: `{ method: 'GET', path: '/api/v1/documents' }`. */
function routeOf(expr: ts.Expression): Route | undefined {
  if (!ts.isObjectLiteralExpression(expr)) return undefined;
  let method = "";
  let path = "";
  for (const prop of expr.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    const key = propertyKey(prop);
    if (key === "method" && ts.isStringLiteralLike(prop.initializer)) {
      method = prop.initializer.text;
    }
    if (key === "path" && ts.isStringLiteralLike(prop.initializer)) {
      path = prop.initializer.text;
    }
  }
  return method && path ? { method, path } : undefined;
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
