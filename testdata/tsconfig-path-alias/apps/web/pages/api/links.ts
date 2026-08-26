// A Next.js route in a monorepo, writing every internal import the way `create-next-app`
// scaffolds it: `@/` and nothing relative. `apps/web/tsconfig.json` is what says `@`
// means `apps/web`, and without reading it none of these specifiers resolves to a file
// in this tree -- so each call lowers as external, the caller's data never enters a
// parameter, and the controller below reads as unreachable code.

import type { NextApiRequest, NextApiResponse } from "next";
import deleteLinks from "@/lib/controllers/deleteLinks";
import { runQuery } from "@/lib/db";
import { describeModel } from "@/models";
// No mapping matches this one and nothing on disk answers it: it is a dependency this
// tree does not contain. It must stay external -- an alias table is a statement about
// the project's OWN names, and a resolver that guesses beyond it would invent callees.
import { renderWidget } from "@ui/widgets";

export default async function links(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "DELETE") {
    // Reaches a shell through the controller, and only if `@/` resolved.
    await deleteLinks(req.query.ids);
    return res.status(200).json({ response: describeModel() });
  }

  if (req.method === "GET") {
    // `@/lib/db` is a DIRECTORY: the file is `apps/web/lib/db/index.ts`.
    return res.status(200).json({ response: await runQuery(req.query.collection) });
  }

  return res.status(405).json({ response: renderWidget(req.query.view) });
}
