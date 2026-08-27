// NEGATIVE: two branches, one check, and the branch without it is covered by another.
//
// `canEditDocument` stands on the update branch only. The delete branch has its own
// question -- `canDeleteDocument` -- and it stands on every way to the write, so the
// operation is decided whichever branch produced the record. A rule that counted checks per
// branch rather than asking what stands over the operation would report this.
import { archive } from "./store";

type Req = { params: Record<string, string>; body: { mode: string } };
type Res = { status(code: number): Res; json(body: unknown): void };

export async function mutateDocument(req: Req, res: Res) {
  let document;
  if (req.body.mode === "edit") {
    document = await archive.loadDraft(req.params.id);
    if (!(await archive.canEditDocument(req, document))) {
      res.status(403).json({ error: "forbidden" });
      return;
    }
  } else {
    document = await archive.loadPublished(req.params.id);
  }

  if (!(await archive.canDeleteDocument(req, document))) {
    res.status(403).json({ error: "forbidden" });
    return;
  }

  await archive.commit(document);
  res.status(200).json({ ok: true });
}
