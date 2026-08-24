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
import type {
  Arg,
  Block,
  Call,
  Callee,
  Comparison,
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

interface FuncMeta {
  id: string;
  name: string;
  moduleId: string;
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
  return (node) => {
    const direct = funcByNode.get(node);
    if (direct) return direct;

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
      if (ts.isPropertyAssignment(decl) && funcByNode.get(decl.initializer)) {
        return funcByNode.get(decl.initializer);
      }
    }
    return undefined;
  };
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

export function lowerProgram(opts: LowerOptions): IRDoc {
  const program = ts.createProgram(opts.files, {
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
  });
  const checker = program.getTypeChecker();

  const sources = program
    .getSourceFiles()
    .filter((sf) => !sf.isDeclarationFile && isUnder(opts.rootDir, sf.fileName));

  const modules: Module[] = [];
  const funcByNode = new Map<ts.Node, FuncMeta>();
  const importsByFile = new Map<ts.SourceFile, Map<string, ImportRef>>();

  for (const sf of sources) {
    const moduleId = moduleIdOf(opts.rootDir, sf.fileName);
    modules.push({ id: moduleId, path: moduleId });
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
    for (const [node, meta] of funcsBySource.get(sf) ?? []) {
      functions.push(
        lowerFunction(node as ts.SignatureDeclaration, meta, sf, checker, imports, resolveFunction, identity),
      );
    }
    entryPoints.push(...detectExpressRoutes(sf, imports, resolveFunction, (n) => locOf(sf, n)));
    entryPoints.push(...detectNestRoutes(sf, resolveFunction, (n) => locOf(sf, n), definedDecorators));
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
      out.set(node, { id: `${moduleId}#${name}:${loc.line}`, name, moduleId });
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
  node: ts.SignatureDeclaration,
  meta: FuncMeta,
  sf: ts.SourceFile,
  checker: ts.TypeChecker,
  imports: Map<string, ImportRef>,
  resolveFunction: FunctionResolver,
  identity: Set<string>,
): FunctionIR {
  const values: Value[] = [];
  const flows: Flow[] = [];
  const calls: Call[] = [];
  const comparisons: Comparison[] = [];
  const blocks: Block[] = [];
  const returns: string[] = [];
  const params: Param[] = [];
  const bySymbol = new Map<ts.Symbol, string>();
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
    return { type: symbol.getName() };
  };

  const addFlow = (from: string | undefined, to: string, kind: Flow["kind"], loc: Loc): void => {
    if (from && to) flows.push({ from, to, kind, loc });
  };

  const bind = (name: ts.Identifier, valueId: string): void => {
    const sym = checker.getSymbolAtLocation(name);
    if (sym) bySymbol.set(sym, valueId);
  };

  const injected = untrustedParams(node);
  const identityInjected = identityParams(node, identity);

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
  node.parameters.forEach((p, index) => {
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

  const isLibDeclared = (name: ts.Node): boolean => {
    const sym = checker.getSymbolAtLocation(name);
    for (const decl of sym?.declarations ?? []) {
      const file = decl.getSourceFile().fileName;
      if (file.includes("/lib.") && file.endsWith(".d.ts")) return true;
    }
    return false;
  };

  const resolveCallee = (call: ts.CallExpression | ts.NewExpression): Callee => {
    const expr = call.expression;

    if (ts.isIdentifier(expr)) {
      const local = localTarget(expr);
      if (local) return { kind: "local", functionId: local, resolution: "resolved" };

      const imported = imports.get(expr.text);
      if (imported && imported.export !== "*") {
        return {
          kind: "external",
          symbol: `${imported.module}.${imported.export}`,
          resolution: "resolved",
        };
      }
      if (isLibDeclared(expr)) {
        return { kind: "external", symbol: expr.text, resolution: "resolved" };
      }
      return { kind: "unresolved", resolution: "dynamic-unresolved" };
    }

    if (ts.isPropertyAccessExpression(expr)) {
      const root = expr.expression;
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
          return {
            kind: "external",
            symbol: `${imported.module}.${expr.name.text}`,
            resolution: "resolved",
          };
        }
      }
      const local = localTarget(expr.name);
      if (local) return { kind: "local", functionId: local, resolution: "resolved" };

      const symbol = `${root.getText(sf)}.${expr.name.text}`;
      return {
        kind: "external",
        symbol,
        resolution: isLibDeclared(expr.name) ? "resolved" : "probable",
      };
    }

    return { kind: "unresolved", resolution: "dynamic-unresolved" };
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

  const lowerProperty = (node2: ts.PropertyAccessExpression): string | undefined => {
    const segments: string[] = [];
    let cur: ts.Expression = node2;
    for (;;) {
      cur = unwrap(cur);
      if (!ts.isPropertyAccessExpression(cur)) break;
      segments.unshift(cur.name.text);
      cur = cur.expression;
    }
    if (!ts.isIdentifier(cur)) return undefined;

    const sym = checker.getSymbolAtLocation(cur);
    const baseId = sym ? bySymbol.get(sym) : undefined;
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

  const lowerExpr = (expr: ts.Expression): string | undefined => {
    if (ts.isParenthesizedExpression(expr)) return lowerExpr(expr.expression);
    if (ts.isAwaitExpression(expr)) return lowerExpr(expr.expression);
    if (ts.isNonNullExpression(expr)) return lowerExpr(expr.expression);
    if (ts.isAsExpression(expr)) return lowerExpr(expr.expression);

    if (ts.isIdentifier(expr)) {
      const sym = checker.getSymbolAtLocation(expr);
      return sym ? bySymbol.get(sym) : undefined;
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
      const id = newValue("property", loc, { base, name: "[index]" });
      addFlow(base, id, "property", loc);
      return id;
    }

    // `new Thing(x)` is a call. Without this, every argument to every constructor
    // vanishes from the dataflow — and one of them is `new Function(src)`, which is
    // an evaluator wearing a different keyword.
    if (ts.isNewExpression(expr)) {
      const loc = locOf(sf, expr);
      const args: Arg[] = [];
      (expr.arguments ?? []).forEach((a, index) => {
        const valueId = lowerExpr(a);
        const fn = resolveFunction(a);
        if (valueId || fn) args.push({ index, valueId, functionId: fn?.id });
      });

      const callee = resolveCallee(expr);
      const resultId = newValue("call-result", loc, { name: callee.symbol ?? callee.kind });
      calls.push({
        id: `${meta.id}$c${callCount++}`,
        loc,
        callee,
        args,
        resultValueId: resultId,
        block: current,
      });
      return resultId;
    }

    if (ts.isCallExpression(expr)) {
      const loc = locOf(sf, expr);

      const args: Arg[] = [];
      const argLiterals: Record<number, string> = {};
      expr.arguments.forEach((a, index) => {
        const valueId = lowerExpr(a);
        const fn = resolveFunction(a);
        if (valueId || fn) args.push({ index, valueId, functionId: fn?.id });
        const lit = literalOf(a);
        if (lit !== undefined) argLiterals[index] = lit;
      });

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
        receiverType: receiverType.type,
        receiverTypeOrigin: receiverType.origin,
        resultValueId: resultId,
        block: current,
      });
      return resultId;
    }

    if (ts.isTemplateExpression(expr)) {
      const loc = locOf(sf, expr);
      const id = newValue("local", loc, { name: "`template`" });
      for (const span of expr.templateSpans) {
        addFlow(lowerExpr(span.expression), id, "template", loc);
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
      for (const el of expr.elements) addFlow(lowerExpr(el), id, "assign", loc);
      return id;
    }

    if (ts.isObjectLiteralExpression(expr)) {
      const loc = locOf(sf, expr);
      const id = newValue("local", loc, { name: "{object}" });
      // Every form that carries a value in. `{ slug }` and `{ ...base }` are how
      // real code builds query objects; handling only `key: value` loses the taint
      // at the last hop before the sink.
      for (const prop of expr.properties) {
        if (ts.isPropertyAssignment(prop)) {
          addFlow(lowerExpr(prop.initializer), id, "assign", loc);
        } else if (ts.isShorthandPropertyAssignment(prop)) {
          // For `{ slug }` the identifier resolves to the PROPERTY symbol, not the
          // local it reads. The checker has a dedicated accessor for the value.
          const valueSym = checker.getShorthandAssignmentValueSymbol(prop);
          const from = valueSym ? bySymbol.get(valueSym) : undefined;
          addFlow(from, id, "assign", loc);
        } else if (ts.isSpreadAssignment(prop)) {
          addFlow(lowerExpr(prop.expression), id, "assign", loc);
        }
      }
      return id;
    }

    if (ts.isStringLiteralLike(expr) || ts.isNumericLiteral(expr)) {
      return newValue("literal", locOf(sf, expr));
    }

    return undefined;
  };

  const walk = (n: ts.Node): void => {
    // Nested functions are separate IR functions; their bodies are not inlined here.
    if (n !== node && isFunctionLike(n)) return;

    if (ts.isVariableDeclaration(n)) {
      const loc = locOf(sf, n);
      const init = n.initializer ? lowerExpr(n.initializer) : undefined;

      if (ts.isIdentifier(n.name)) {
        const id = newValue("local", loc, { name: n.name.text });
        bind(n.name, id);
        addFlow(init, id, "assign", loc);
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
    if (ts.isExpressionStatement(n)) {
      lowerExpr(n.expression);
      return;
    }
    ts.forEachChild(n, walk);
  };

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
