// Reached through `@shared/audit`, which is declared in `tsconfig.base.json` and read
// here only by following `apps/api/tsconfig.json`'s `extends` to it.

import { exec } from "node:child_process";

export function auditLog(entry: string) {
  exec(`logger -t audit ${entry}`);
}
