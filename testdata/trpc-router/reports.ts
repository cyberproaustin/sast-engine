import { exec } from "node:child_process";

import { authenticatedProcedure, procedure, router } from "./trpc.ts";

/**
 * A procedure exported on its own, composed into a router by another file.
 *
 * This is the shape that makes the address a program-wide question: nothing here says
 * where it is served, and the file that does never mentions what it contains.
 */
export const exportReportRoute = authenticatedProcedure
  .meta({ openapi: { method: "POST", path: "/report/export" } })
  .input({})
  .mutation(async ({ input }) => {
    // The caller names the report and the name is interpolated into a shell command.
    exec(`report-tool --export ${input.name}`);
    return { ok: true };
  });

export const reportRouter = router({
  export: exportReportRoute,

  // A read the caller cannot steer: the command is written here in full.
  list: authenticatedProcedure.query(async () => {
    exec("report-tool --list");
    return { ok: true };
  }),

  // No authentication middleware, and its peers have one. Nothing dangerous happens
  // inside it; what it is here for is the CONTROL the surface records against it.
  status: procedure.query(async () => {
    return { ok: true };
  }),
});
