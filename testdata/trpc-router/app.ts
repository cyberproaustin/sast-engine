import { reportRouter } from "./reports.ts";
import { authenticatedProcedure, router } from "./trpc.ts";

/**
 * The root router. Every address in this application is a key from HERE joined to a key
 * in the file that declares the procedure, and the two files never mention each other's
 * contents.
 */
export const appRouter = router({
  report: reportRouter,
  admin: router({
    purge: authenticatedProcedure.input({}).mutation(async ({ input }) => {
      return { purged: input.olderThan };
    }),
  }),
});

/**
 * Not a procedure, and the reason it is not is worth stating: the terminal name is the
 * same. A cache, a query client and half the ORMs in existence expose `mutation` and
 * `query`, so a model keyed on the terminal alone would enumerate this as a route. What
 * is missing is the builder -- no `input`, no `meta`, no `use` -- and a receiver that
 * says it is a procedure.
 */
declare const queryClient: { mutation(fn: () => void): void };
queryClient.mutation(() => {
  // deliberately empty
});
