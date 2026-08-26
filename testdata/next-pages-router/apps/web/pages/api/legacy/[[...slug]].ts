// The optional catch-all, which serves `/api/legacy` itself as well as everything under
// it. It lowers to the same wildcard the required form does: `*` already stands for the
// rest of a path, and the App Router shares this derivation.

import type { NextApiRequest, NextApiResponse } from "next";
import { redirectLegacy } from "../../../../lib/upstream";

export default async function legacy(req: NextApiRequest, res: NextApiResponse) {
  return res.status(200).json({ response: await redirectLegacy(req.query.slug) });
}
