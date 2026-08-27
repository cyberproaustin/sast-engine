// One of two packages in this tree that publish the name `@acme/twins`. The shell below
// is reachable only if a resolver picked THIS directory over its twin -- and nothing in
// the tree says it should. It must never be reported.

import { exec } from "node:child_process";

export function sweep(pattern: unknown) {
  exec(`sweep-tool --pattern ${pattern}`);
}
