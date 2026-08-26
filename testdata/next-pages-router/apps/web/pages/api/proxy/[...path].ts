// A catch-all: every segment below `/api/proxy` reaches this one handler, which is why
// the path it stands for is a wildcard rather than the literal directory name.

import type { NextApiRequest, NextApiResponse } from "next";
import { forward } from "../../../../lib/upstream";

export default async function proxy(req: NextApiRequest, res: NextApiResponse) {
  return res.status(200).json({ response: await forward(req.query.path) });
}
