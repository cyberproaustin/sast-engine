import express from "express";
import { exec } from "child_process";
import { makeBadge } from "badge-maker";

const app = express();

// The uptime-kuma shape, and the question this corpus settles. `badge-maker` is pinned in
// a lockfile and its source is not in this tree, so whether the caller's text survives
// makeBadge unescaped is not something this repository establishes. The taint keeps
// flowing, because an unknown callee has no known semantics and over-approximating is the
// only safe reading of nothing -- and the finding now says which hop was assumed, which is
// what turns "disputed" into a question a reader can go and answer.
app.get("/badge", (req, res) => {
  const svg = makeBadge({ label: "status", message: req.query.style });
  res.send(svg); // EXPECTED FINDING: CWE-79, and the makeBadge hop is assumed
});

// The contrast, and the reason the discriminator is not merely "external". This model has
// a statement about encodeURIComponent: it clears a URL context and nothing else. That is
// insufficient for a shell and the finding is reported -- and nothing on this path was
// assumed, because the engine was not guessing about what the call does.
app.get("/run", (req, res) => {
  const host = encodeURIComponent(req.query.host as string);
  exec(`ping -c 1 ${host}`); // EXPECTED FINDING: CWE-78, nothing assumed
  res.send("ok");
});

app.listen(3000);
