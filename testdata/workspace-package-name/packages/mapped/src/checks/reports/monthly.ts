// Reached as `@acme/mapped/reports/monthly`, through the `./reports/*` pattern in the
// manifest's `exports` map -- a wildcard whose target directory is not the subpath.

import { exec } from "node:child_process";

export function monthly(period: unknown) {
  exec(`report-tool monthly --period ${period}`);
  return "";
}
