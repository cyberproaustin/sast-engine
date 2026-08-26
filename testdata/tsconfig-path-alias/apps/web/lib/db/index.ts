// `@/lib/db` names this directory, not a file: `index.ts` is what answers it.

import { exec } from "node:child_process";

export async function runQuery(collection: unknown) {
  exec(`db-cli select --from ${collection}`);
  return [];
}
