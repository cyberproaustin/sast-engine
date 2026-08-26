// Reached through `@acme/shared`: a workspace package NAME, mapped without a wildcard.
// This is how a monorepo refers to its own packages, and it is the same machinery.

import { exec } from "node:child_process";

export function runReport(name: string) {
  exec(`report-tool --name ${name}`);
}
