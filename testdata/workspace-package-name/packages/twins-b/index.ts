// The other `@acme/twins`. Identical export, different body: which one `sweep` means is
// exactly the question the tree cannot answer, so the specifier resolves to nothing.

import { exec } from "node:child_process";

export function sweep(pattern: unknown) {
  exec(`sweep-tool --legacy --pattern ${pattern}`);
}
