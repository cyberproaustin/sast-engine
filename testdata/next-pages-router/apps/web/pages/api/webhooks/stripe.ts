// The 405 guard: `req.method !== "POST"` names POST exactly as `=== "POST"` does, and
// it is how a single-verb route is usually written.
//
// The default export is an identifier rather than a declaration, which is the shape
// that has to resolve before the route can name its handler at all.

import type { NextApiRequest, NextApiResponse } from "next";
import { recordEvent } from "../../../../lib/billing";

async function stripeWebhook(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    return res.status(405).json({ response: "Method not allowed." });
  }

  await recordEvent(req.body);
  return res.status(200).json({ received: true });
}

export default stripeWebhook;
