// NEGATIVE -- the same thing one directory down, with a dynamic segment. `pages/api` is
// matched as a SUFFIX so that a monorepo can put it anywhere, and a rule that only asked
// whether `pages` appears somewhere in the path would take this for a route.

import React from "react";

export default function TeamSettings() {
  return <section>Team settings</section>;
}
