/**
 * SILENT AS APPLICATION SURFACE -- a dev-watch script.
 *
 * This is a real recurring callback and it is enumerated as one, with the callback
 * resolved. It is not the APPLICATION's surface: it runs on a developer's machine when
 * somebody types a build command, and counting it beside the routes an operator is meant
 * to audit is the same category error as counting an example route.
 *
 * `scripts/` counts only because it is the first segment of the package. A rule that
 * matched `scripts` at any depth would have deleted a live umami endpoint served from
 * `src/app/api/scripts/telemetry/route.ts`, which is a much worse trade: the surface may
 * not over-report, and it may not drop a real route either.
 */
function rebuild(): void {
  void Date.now();
}

setInterval(rebuild, 1000);
