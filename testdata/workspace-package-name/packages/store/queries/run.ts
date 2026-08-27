// Reached as `@acme/store/queries/run`: a subpath under a package that declares no
// `exports`, so the path is taken relative to the package's own directory.

import { exec } from "node:child_process";

export function runQuery(collection: unknown) {
  exec(`store-cli query --collection ${collection}`);
  return [];
}
