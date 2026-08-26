import { z } from "zod";

import { HOSTNAME_LABEL } from "./patterns";

// NEGATIVE. The same schema field as the reported one, in a module no entry point
// reaches. The pattern is exactly as catastrophic here as it is in the route; what is
// missing is anybody able to send it a string, and a rule that reports this has stopped
// making a claim about the attack surface (ADR-009).
export function buildImportSchema() {
  return z.object({
    domain: z.string().trim().regex(HOSTNAME_LABEL).max(500),
  });
}
