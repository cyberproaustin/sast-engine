// The controller a route calls. Its parameter carries whatever the caller sent, and it
// is a parameter of a function nothing could reach until `@/` resolved.
//
// `@/generated/...` is tried before `@/...` by the mapping, so this file answers the
// specifier only because no `apps/web/generated/lib/controllers/deleteLinks.ts` exists.

import { exec } from "node:child_process";

export default async function deleteLinks(ids: unknown) {
  exec(`link-tool purge --ids ${ids}`);
  return { deleted: ids };
}
