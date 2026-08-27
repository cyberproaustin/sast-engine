// Reached as `@acme/store`: the bare package NAME, answered by this manifest's `main`.

import { exec } from "node:child_process";

export function purgeLinks(ids: unknown) {
  exec(`link-tool purge --ids ${ids}`);
}
