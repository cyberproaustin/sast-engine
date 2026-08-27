// Reached as `@acme/mapped/audit`, and ONLY through the manifest's `exports` map: the
// conventional roots would look at `packages/mapped/audit` and `packages/mapped/src/audit`
// and find neither.

import { exec } from "node:child_process";

export function recordAudit(entry: unknown) {
  exec(`audit-tool append --entry ${entry}`);
}
