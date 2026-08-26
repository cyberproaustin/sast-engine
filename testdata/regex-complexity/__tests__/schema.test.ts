import express from "express";
import { z } from "zod";

import { HOSTNAME_LABEL } from "../patterns";

// NEGATIVE. A route registered in a test file is a fixture, not an attack surface. The
// entry point is enumerated -- the frontend cannot tell one `app.post` from another -- so
// silence here has to be stated by the rule rather than fall out of reachability.
const app = express();

app.post("/websites", (_req, res) => {
  const schema = z.object({
    domain: z.string().trim().regex(HOSTNAME_LABEL).max(500),
  });
  res.json({ fields: Object.keys(schema.shape) });
});

export default app;
