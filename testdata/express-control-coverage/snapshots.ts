// The positive this corpus exists for: one handler, one record, two ways to get it, and
// the access check standing on only one of them.
//
// Both branches assign `snapshot` and both fall through to the same redirect, so whichever
// way the request came in, the same record is served. `canViewSnapshot` decides the first
// way and nothing decides the second. The check is not missing from the program -- it is
// four lines up, spelled correctly, over this very value.
import { archive, lookupById, publicQuery } from "./store";

type Req = { params: Record<string, string>; query: Record<string, string> };
type Res = { status(code: number): Res; json(body: unknown): void; redirect(to: string): void };

export async function serveSnapshot(req: Req, res: Res) {
  const { owner, snapshotId, slug } = req.params;

  let snapshot;
  if (snapshotId) {
    snapshot = await lookupById(snapshotId);
    if (snapshot && !(await archive.canViewSnapshot(req, snapshot))) {
      res.status(403).json({ error: "forbidden" });
      return;
    }
  } else {
    snapshot = await publicQuery(owner, slug);
  }

  if (!snapshot) {
    res.status(404).json({ error: "no such snapshot" });
    return;
  }

  res.redirect(`/${snapshot.path}/index.html`);
}
