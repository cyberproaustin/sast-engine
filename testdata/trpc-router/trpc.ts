// The application's own re-export of the tRPC builder, which is how every tRPC codebase
// of any size is written: `initTRPC` is called once, and the rest of the program imports
// the names bound here. Declared rather than implemented, because what the engine reads
// is the SHAPE a procedure chain has and not what the builder does at runtime.

export interface Meta {
  openapi?: { method: string; path: string; enabled?: boolean };
}

export interface Builder {
  meta(meta: Meta): Builder;
  input(schema: unknown): Builder;
  output(schema: unknown): Builder;
  use(middleware: unknown): Builder;
  query(handler: (opts: { ctx: Context; input: any }) => unknown): unknown;
  mutation(handler: (opts: { ctx: Context; input: any }) => unknown): unknown;
}

export interface Context {
  user: { id: string };
}

export declare function router<T>(routes: T): T;

/** No middleware: anyone who can reach the server can call these. */
export declare const procedure: Builder;

/** The same builder with an authentication middleware already applied. */
export declare const authenticatedProcedure: Builder;
