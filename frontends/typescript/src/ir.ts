// Program IR — the wire contract with the core (docs/IR.md, ADR-001).
// Types only. This file must stay a mirror of the spec, not of the TypeScript AST.

export const IR_VERSION = "0.9.0";

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
}

export interface Flow {
  from: string;
  to: string;
  kind: "assign" | "property" | "template" | "binary" | "return";
  loc: Loc;
}

export type Resolution = "resolved" | "probable" | "dynamic-unresolved";

export interface Callee {
  kind: "local" | "external" | "unresolved";
  functionId?: string;
  symbol?: string;
  resolution: Resolution;
}

export interface Arg {
  index: number;
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
  /** Literal argument values by index, for defects visible in the call itself. */
  argLiterals?: Record<number, string>;
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

export interface EntryPoint {
  functionId: string;
  kind: string;
  framework?: string;
  detail?: Record<string, string>;
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
