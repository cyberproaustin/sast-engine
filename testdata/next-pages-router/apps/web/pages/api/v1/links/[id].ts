// The parameter is in the FILE name here, not in a directory -- the one place the two
// Next.js routers disagree about where a path segment comes from.
//
// A switch is the other way a handler dispatches, and it has to be read as one: a body
// scanned only for `===` reports this route as answering every verb.

import type { NextApiRequest, NextApiResponse } from "next";
import { getLink, updateLink, removeLink } from "../../../../lib/links";

export default async function link(req: NextApiRequest, res: NextApiResponse) {
  const id = Number(req.query.id);

  switch (req.method) {
    case "GET":
      return res.status(200).json({ response: await getLink(id) });
    case "PUT":
      return res.status(200).json({ response: await updateLink(id, req.body) });
    case "DELETE":
      return res.status(200).json({ response: await removeLink(id) });
    default:
      return res.status(405).json({ response: "Method not allowed." });
  }
}
