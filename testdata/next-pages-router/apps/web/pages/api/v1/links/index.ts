// `index` is the directory, so this is `/api/v1/links` and not `/api/v1/links/index`.
//
// Two verbs in one file, chosen by an if-chain on `req.method`. Each branch is a
// separately reachable handler: a caller who can reach the POST branch has done
// something the GET branch never allowed, and one entry point covering both would say
// they are the same route.

import type { NextApiRequest, NextApiResponse } from "next";
import { listLinks, createLink } from "../../../../lib/links";

export default async function links(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    return res.status(200).json({ response: await listLinks(req.query.collection) });
  } else if (req.method === "POST") {
    return res.status(201).json({ response: await createLink(req.body) });
  }

  return res.status(405).json({ response: "Method not allowed." });
}
