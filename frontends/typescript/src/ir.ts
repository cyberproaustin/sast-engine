// Program IR — the wire contract with the core (docs/IR.md, ADR-001).
// Types only. This file must stay a mirror of the spec, not of the TypeScript AST.

export const IR_VERSION = "0.17.0";

export interface Loc {
  file: string;
  line: number;
  column: number;
}

export interface Capabilities {
  typeChecker: boolean;
  interprocedural: boolean;
  crossModule: boolean;
  controlFlow: boolean;
  /** Whether view templates were read as well as source. */
  templates?: boolean;
  frameworkModels: string[];
}

export interface Frontend {
  name: string;
  version: string;
  capabilities: Capabilities;
}

export interface Module {
  id: string;
  path: string;
  /** Ships with the code but does not run in production. */
  isTest?: boolean;
  /** Why this is not hand-written application source. */
  provenance?: "vendored" | "example" | "generated";
  /**
   * No other module in this program names it, and no framework convention loads it.
   *
   * A graph fact, not a judgement: the frontend says which modules nothing reaches and
   * the core decides what that means, which is the same division `isTest` and
   * `provenance` already draw. Set only where the answer is decidable -- every import,
   * re-export, `require` and dynamic `import()` in the program was resolved, and the
   * module is not one a framework loads by PATH rather than by name.
   */
  unreferenced?: boolean;
}

export type ValueKind =
  | "param"
  | "local"
  | "property"
  | "call-result"
  | "literal"
  | "catch-param"
  | "untrusted-param"
  | "actor-identity-param";

export interface Value {
  id: string;
  kind: ValueKind;
  name?: string;
  loc: Loc;
  base?: string;
  path?: string;
  /** The text of a value written into the source, for the kinds that have one. */
  literal?: string;
}

export interface Flow {
  from: string;
  to: string;
  /** "enclose" = the value became a PART of a structure rather than becoming it. */
  kind: "assign" | "property" | "template" | "binary" | "return" | "enclose";
  loc: Loc;
  /**
   * The basic block this edge runs in. Left UNSET wherever the block graph does not
   * express when the edge runs -- inside a loop, whose back edge is not emitted, or
   * inside a `switch`, whose arms are lowered straight-line. The core reads an absent
   * block as "position unknown" and keeps the flow.
   */
  block?: string;
}

export type Resolution = "resolved" | "probable" | "dynamic-unresolved";

export interface Callee {
  kind: "local" | "external" | "unresolved";
  functionId?: string;
  /** Finite targets of an indirect call whose runtime selection is not known. */
  possibleFunctionIds?: string[];
  symbol?: string;
  resolution: Resolution;
  /** What the call was WRITTEN as, independently of what it resolved to. */
  name?: string;
}

export interface Arg {
  /** Positional index; absent for a named argument. */
  index?: number;
  /** Keyword name; absent for a positional argument. */
  name?: string;
  valueId?: string;
  /** Set when the argument is a function value (callback, promise continuation). */
  functionId?: string;
}

export interface Call {
  id: string;
  loc: Loc;
  callee: Callee;
  args: Arg[];
  /** Property name for a method call, independent of how the receiver was spelled. */
  method?: string;
  /** The value the method was invoked on. */
  receiverValueId?: string;
  resultValueId?: string;
  block?: string;
  /** Which call result enters a branch's first successor, when this call is its direct condition. */
  conditionBranch?: "truthy" | "falsy";
  /** Literal argument values by index, for defects visible in the call itself. */
  argLiterals?: Record<number, string>;
  argCount?: number;
  enumeratedOptions?: number[];
  /** The receiver's type, for evidence. Absent when the checker cannot say. */
  receiverType?: string;
  /** Where that type is declared. "builtin" = the language's own standard library. */
  receiverTypeOrigin?: string;
}

export interface Param {
  index: number;
  name: string;
  valueId: string;
}

export interface Comparison {
  left: string;
  right: string;
  op: string;
  block?: string;
  loc: Loc;
}

export interface Block {
  id: string;
  successors?: string[];
  terminator?: string;
  loc: Loc;
}

export interface Write {
  loc: Loc;
  base?: string;
  path?: string;
  from?: string;
  /**
   * The value the entry was filed under, for a subscript whose key was COMPUTED.
   * `path` carries a key written as a literal; the two are never both set.
   */
  key?: string;
  /** The basic block the write occurs in; unset inside a loop body or a switch arm. */
  block?: string;
  /** How far the destination reaches: "process" for state shared by every request. */
  scope?: string;
}

export interface FunctionIR {
  id: string;
  name: string;
  module: string;
  loc: Loc;
  params: Param[];
  values: Value[];
  flows: Flow[];
  calls: Call[];
  returns: string[];
  comparisons?: Comparison[];
  writes?: Write[];
  entryBlock?: string;
  blocks?: Block[];
}

export interface MiddlewareRef {
  functionId?: string;
  symbol?: string;
  name?: string;
  /** "route" = bound to this registration, "app" = applied application-wide. */
  scope: string;
  loc: Loc;
}

/** Who can cause an entry point to run. Absent is read as "remote". */
export type Trust = "remote" | "operator" | "internal";

export interface EntryPoint {
  functionId: string;
  kind: string;
  framework?: string;
  detail?: Record<string, string>;
  /** Who can trigger it. Unset means remote, which is what every route is. */
  trust?: Trust;
  /** Where the route is registered. */
  loc?: Loc;
  /** The chain applied before the handler runs; where cross-cutting controls live. */
  middleware?: MiddlewareRef[];
  /** Injected inputs whose defining decorator is not in the scanned tree. */
  unresolvedParams?: string[];
}

export interface IRDoc {
  irVersion: string;
  frontend: Frontend;
  modules: Module[];
  functions: FunctionIR[];
  entryPoints: EntryPoint[];
}
