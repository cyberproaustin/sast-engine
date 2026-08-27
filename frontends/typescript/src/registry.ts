// A registration whose PATH is a loop variable.
//
// An application with 438 endpoints registered two of them. `endpoint-list.ts` holds 438
// `export * as <name> from './endpoints/<name>'` lines, a loop walks that array, and the
// body calls `fastify.all('/' + endpoint.name, handler)` in each of two branches -- so the
// frontend matched the two calls, lowered each body once, and recorded two anonymous rows
// at `<unresolved:endpoint.name>` for an entire API. That is not a small loss of detail:
// the enumerated surface is the primary output (ADR-009), and two rows in place of 438
// addresses makes every count that rests on it a rounding error.
//
// The iterated collection is the whole question, and it is answerable HERE rather than at
// runtime: `Object.entries(namespace)` over a module's re-exports is a set of names the
// compiler already knows, an object literal's keys are its properties, and an array of
// literals is itself. Anything else -- a collection built from a database, a filter, a
// value this cannot follow -- resolves to nothing and the registration keeps the single
// unresolved row it has today. Over-reporting the surface is worse than under-reporting
// it: 438 phantom addresses would be far more damaging than one honest `<unresolved>`.

import ts from "typescript";

/**
 * The names a statically enumerable collection holds.
 *
 * `property` is where each element spells its own name -- `endpoint.name` -- or "" when
 * the element IS the name, as it is for `Object.keys(...)` and an array of strings. That
 * distinction is what lets the path expression be folded: `'/' + endpoint.name` and
 * `'/' + name` are the same registration written over two different collections.
 */
export interface NameSet {
  names: string[];
  property: string;
}

export type RegistryResolver = (expr: ts.Expression) => NameSet | undefined;

// A collection reached through more hops than this is not one a reader would call
// static either. The guard is on depth rather than on a seen-set because the hops are
// declarations, and a declaration cycle would not terminate on identity alone.
const MAX_HOPS = 8;

export function makeRegistryResolver(checker: ts.TypeChecker): RegistryResolver {
  /** Where a name was declared, following imports and `export default` to the value. */
  const declaredValue = (expr: ts.Expression): ts.Expression | undefined => {
    if (!ts.isIdentifier(expr)) return undefined;
    let sym = checker.getSymbolAtLocation(expr);
    if (!sym) return undefined;
    if (sym.flags & ts.SymbolFlags.Alias) {
      try {
        sym = checker.getAliasedSymbol(sym);
      } catch {
        return undefined;
      }
    }
    for (const decl of sym.declarations ?? []) {
      if (ts.isVariableDeclaration(decl) && decl.initializer) return decl.initializer;
      // `export default endpoints` -- the default export of a module is an assignment,
      // and the value is one more hop through the name it assigns.
      if (ts.isExportAssignment(decl) && !decl.isExportEquals) return decl.expression;
    }
    return undefined;
  };

  /** The names a module namespace or an object literal exposes. */
  const memberNames = (expr: ts.Expression | undefined, depth: number): string[] | undefined => {
    if (!expr || depth > MAX_HOPS) return undefined;

    if (ts.isObjectLiteralExpression(expr)) {
      const out: string[] = [];
      for (const prop of expr.properties) {
        if (!prop.name) return undefined;
        if (ts.isIdentifier(prop.name) || ts.isStringLiteralLike(prop.name)) out.push(prop.name.text);
        else return undefined;
      }
      return out.length > 0 ? out : undefined;
    }

    if (ts.isIdentifier(expr)) {
      // `import * as endpointsObject from './endpoint-list.js'` -- the compiler already
      // holds every name that module exports, which is exactly the set the loop walks.
      let sym = checker.getSymbolAtLocation(expr);
      if (sym && sym.flags & ts.SymbolFlags.Alias) {
        try {
          sym = checker.getAliasedSymbol(sym);
        } catch {
          sym = undefined;
        }
      }
      if (sym && sym.flags & ts.SymbolFlags.Module) {
        const names = checker.getExportsOfModule(sym).map((s) => s.name);
        if (names.length > 0) return names;
      }
      return memberNames(declaredValue(expr), depth + 1);
    }

    return undefined;
  };

  /**
   * Which property of a `.map` callback's result holds the KEY it was given.
   *
   * `Object.entries(ns).map(([name, ep]) => ({ name: name, meta: ep.meta }))` re-shapes
   * the collection without changing what identifies an element, and the registration is
   * written against the new shape. Answering this is what carries the name set across
   * the map; a callback that does anything else answers nothing.
   */
  const nameCarriedBy = (cb: ts.Expression): string | undefined => {
    if (!ts.isArrowFunction(cb) && !ts.isFunctionExpression(cb)) return undefined;
    const param = cb.parameters[0]?.name;
    if (!param) return undefined;

    // `([name, ep]) => ...` from Object.entries, or `(name) => ...` from Object.keys.
    let keyName: string | undefined;
    if (ts.isArrayBindingPattern(param)) {
      const first = param.elements[0];
      if (first && ts.isBindingElement(first) && ts.isIdentifier(first.name)) keyName = first.name.text;
    } else if (ts.isIdentifier(param)) {
      keyName = param.text;
    }
    if (!keyName) return undefined;

    let result: ts.Expression | undefined;
    if (ts.isBlock(cb.body)) {
      for (const stmt of cb.body.statements) {
        if (ts.isReturnStatement(stmt) && stmt.expression) result = stmt.expression;
      }
    } else {
      result = cb.body;
    }
    if (!result) return undefined;
    if (ts.isParenthesizedExpression(result)) result = result.expression;
    if (!ts.isObjectLiteralExpression(result)) return undefined;

    for (const prop of result.properties) {
      if (ts.isShorthandPropertyAssignment(prop) && prop.name.text === keyName) return prop.name.text;
      if (
        ts.isPropertyAssignment(prop) &&
        (ts.isIdentifier(prop.name) || ts.isStringLiteralLike(prop.name)) &&
        ts.isIdentifier(prop.initializer) &&
        prop.initializer.text === keyName
      ) {
        return prop.name.text;
      }
    }
    return undefined;
  };

  const resolve = (expr: ts.Expression, depth: number): NameSet | undefined => {
    if (depth > MAX_HOPS) return undefined;

    if (ts.isParenthesizedExpression(expr)) return resolve(expr.expression, depth + 1);
    if (ts.isAsExpression(expr) || ts.isSatisfiesExpression(expr)) {
      return resolve(expr.expression, depth + 1);
    }

    if (ts.isArrayLiteralExpression(expr)) {
      if (expr.elements.length === 0) return undefined;
      // An array of names.
      if (expr.elements.every((e) => ts.isStringLiteralLike(e))) {
        return { names: expr.elements.map((e) => (e as ts.StringLiteralLike).text), property: "" };
      }
      // An array of descriptions, each naming itself with the same property.
      const named: string[] = [];
      let property = "";
      for (const element of expr.elements) {
        if (!ts.isObjectLiteralExpression(element)) return undefined;
        let found: string | undefined;
        for (const prop of element.properties) {
          if (!ts.isPropertyAssignment(prop) || !ts.isStringLiteralLike(prop.initializer)) continue;
          if (!ts.isIdentifier(prop.name) && !ts.isStringLiteralLike(prop.name)) continue;
          const key = prop.name.text;
          if (property && key !== property) continue;
          if (!property || key === property) {
            property = key;
            found = prop.initializer.text;
            break;
          }
        }
        if (!found) return undefined;
        named.push(found);
      }
      return property ? { names: named, property } : undefined;
    }

    if (ts.isCallExpression(expr) && ts.isPropertyAccessExpression(expr.expression)) {
      const method = expr.expression.name.text;
      const receiver = expr.expression.expression;

      if (
        (method === "keys" || method === "entries") &&
        ts.isIdentifier(receiver) &&
        receiver.text === "Object"
      ) {
        const names = memberNames(expr.arguments[0], depth + 1);
        return names ? { names, property: "" } : undefined;
      }

      if (method === "map") {
        const inner = resolve(receiver, depth + 1);
        if (!inner || !expr.arguments[0]) return undefined;
        const property = nameCarriedBy(expr.arguments[0]);
        return property ? { names: inner.names, property } : undefined;
      }

      return undefined;
    }

    if (ts.isIdentifier(expr)) {
      const value = declaredValue(expr);
      return value ? resolve(value, depth + 1) : undefined;
    }

    return undefined;
  };

  return (expr) => {
    const found = resolve(expr, 0);
    if (!found || found.names.length === 0) return undefined;
    return found;
  };
}
