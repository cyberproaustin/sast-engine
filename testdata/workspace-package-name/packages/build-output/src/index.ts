// Reached as `@acme/build-output`. Every entry the manifest declares -- `exports`,
// `types`, `module`, `main` -- names a `dist/` this checkout has never built, so the
// declared answers all probe to nothing and the package's own source entry is the one
// file left. Rejecting a build product is deliberate: it carries no body to follow, and
// the source it was generated from is right here.

import { exec } from "node:child_process";

export function renderReport(name: unknown) {
  exec(`report-tool render --name ${name}`);
  return "";
}
