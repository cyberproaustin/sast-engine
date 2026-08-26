// Negative: a read path and a write path that legitimately differ.
//
// The write asks permission and the read does not, which is the ordinary asymmetry of
// every application ever written -- the direction this rule fires in is the OPPOSITE one,
// and that is the whole of what keeps it quiet here.
import { featureService } from "./service";

type Req = { params: Record<string, string>; body: unknown; user: { id: string } };
type Res = { status(code: number): Res; json(body: unknown): void };

export async function getSegments(req: Req, res: Res) {
  const { projectId } = req.params;
  const segments = await featureService.readSegments(projectId);
  res.status(200).json({ segments });
}

export async function createSegment(req: Req, res: Res) {
  const { projectId } = req.params;
  const allowed = await featureService.hasPermission(req.user, projectId);
  if (!allowed) {
    res.status(403).json({ error: "forbidden" });
    return;
  }
  await featureService.saveSegment(projectId, req.body);
  res.status(201).json({ ok: true });
}
