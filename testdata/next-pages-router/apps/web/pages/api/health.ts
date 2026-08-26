// A Pages Router handler that does not ask which verb it was given. Next.js hands it
// every method, so ANY is what this route actually serves -- naming a verb here would
// be inventing one the file never states.

import type { NextApiRequest, NextApiResponse } from "next";

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  res.status(200).json({ status: "ok" });
}
