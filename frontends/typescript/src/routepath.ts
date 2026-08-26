// What a route is registered AT, when the registration does not spell it as a literal.
//
// Shared by every framework model in this frontend rather than written once per model:
// `app.get(`${baseUriPath}/api`, ...)`, `@Controller(PREFIX)` and a file-route segment
// are one question asked by three registrars, and the answer has to read the same way in
// all three or the surface cannot be scanned by one eye (ADR-004).

import ts from "typescript";

/**
 * The marker for a path the frontend could not read.
 *
 * `*` was what these used to print, and `*` is a CLAIM: it says the route matches
 * everything. That is both different from and stronger than "this expression was not
 * resolvable", and an operator checking their application against the surface cannot
 * tell the two apart. ADR-009 asks for a route that exists to appear; it does not ask
 * for it to state a false address.
 */
export const UNRESOLVED_PATH = "<unresolved>";

/** The unresolved marker, naming the expression that stood in the way. */
export function unresolvedPath(expr = ""): string {
  return expr ? `<unresolved:${expr}>` : UNRESOLVED_PATH;
}

export function isUnresolvedPath(path: string): boolean {
  return path.startsWith("<unresolved");
}

/** A mount prefix concatenated with the path registered under it. */
export function joinRoute(prefix: string, path: string): string {
  if (!prefix) return path;
  if (!path) return prefix;
  return prefix.replace(/\/+$/, "") + "/" + path.replace(/^\/+/, "");
}

/**
 * Every name bound to an expression in this file, so a path written as a name resolves.
 *
 * First binding wins, which is how the file reads: a name reassigned further down is
 * still the one the registration above it was written against.
 */
export function collectStringBindings(sf: ts.SourceFile): Map<string, ts.Expression> {
  const out = new Map<string, ts.Expression>();
  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      if (!out.has(node.name.text)) out.set(node.name.text, node.initializer);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

/**
 * A route path as the source wrote it, resolved as far as the file allows.
 *
 * A DEFAULT is resolved rather than refused. `config.server.baseUriPath || ''` names the
 * address of every deployment that leaves the setting alone, which is the same judgement
 * the Django URLconf model already makes about a setting interpolated into a route: the
 * static text is the route until an operator changes it, and the cost of a prefix that
 * may be wrong is far below the cost of no path at all (ADR-009).
 *
 * What genuinely cannot be read is NAMED. `<unresolved:baseUriPath>/api` says which
 * expression stood in the way, which is the difference between an operator being able to
 * look it up and being told the route matches everything.
 */
export function pathText(
  expr: ts.Expression | undefined,
  consts: Map<string, ts.Expression>,
  seen: ReadonlySet<string> = new Set(),
): string {
  if (!expr) return UNRESOLVED_PATH;

  if (ts.isStringLiteralLike(expr)) return expr.text;

  // A regex route's address IS the regex. Printing it is the honest answer; the
  // alternative was `*`, which claims the route matches strictly more than it does.
  if (ts.isRegularExpressionLiteral(expr)) return expr.text;

  if (ts.isParenthesizedExpression(expr)) return pathText(expr.expression, consts, seen);

  if (ts.isTemplateExpression(expr)) {
    let out = expr.head.text;
    for (const span of expr.templateSpans) {
      out += pathText(span.expression, consts, seen) + span.literal.text;
    }
    return out;
  }

  if (ts.isIdentifier(expr)) {
    const bound = consts.get(expr.text);
    if (bound && !seen.has(expr.text)) {
      const text = pathText(bound, consts, new Set([...seen, expr.text]));
      if (!isUnresolvedPath(text)) return text;
    }
    return unresolvedPath(expr.text);
  }

  if (ts.isBinaryExpression(expr)) {
    const op = expr.operatorToken.kind;
    if (op === ts.SyntaxKind.PlusToken) {
      return pathText(expr.left, consts, seen) + pathText(expr.right, consts, seen);
    }
    // `x || '/base'` and `x ?? '/base'`: the right side is the default, and the default
    // is the address until somebody configures otherwise.
    if (op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken) {
      const left = pathText(expr.left, consts, seen);
      if (!isUnresolvedPath(left)) return left;
      return pathText(expr.right, consts, seen);
    }
    return UNRESOLVED_PATH;
  }

  if (ts.isPropertyAccessExpression(expr)) {
    return unresolvedPath(expr.getText(expr.getSourceFile()));
  }

  if (ts.isCallExpression(expr)) {
    const callee = expr.expression;
    // `.replace(...)` and the trim family are how a configured prefix is normalised
    // before it is used, and refusing them loses a prefix that was otherwise readable.
    if (ts.isPropertyAccessExpression(callee)) {
      const base = pathText(callee.expression, consts, seen);
      if (!isUnresolvedPath(base)) {
        const name = callee.name.text;
        if (name === "trim") return base.trim();
        if (name === "replace" || name === "replaceAll") {
          const [pattern, replacement] = expr.arguments;
          if (
            pattern &&
            replacement &&
            ts.isStringLiteralLike(pattern) &&
            ts.isStringLiteralLike(replacement)
          ) {
            return name === "replace"
              ? base.replace(pattern.text, replacement.text)
              : base.replaceAll(pattern.text, replacement.text);
          }
        }
      }
      return unresolvedPath(callee.getText(callee.getSourceFile()));
    }
    return unresolvedPath(ts.isIdentifier(callee) ? callee.text : "");
  }

  return UNRESOLVED_PATH;
}
