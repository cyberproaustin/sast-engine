// NEGATIVE: a public route beside a protected one, which is a design and not a defect.
//
// This is the shape the convention analysis reported for a year and was told to stop
// reporting: medplum mounts a public FHIR router beside a protected one deliberately, and
// no name list can tell that apart from an endpoint whose author forgot. What clears it
// here is not a better list -- it is that the two handlers CONVERGE on nothing. They share
// no value, they end at different calls, and the graph offers no reason to believe the
// author meant them to be alike.
import { archive, healthOf } from "./store";

type Req = { params: Record<string, string> };
type Res = { status(code: number): Res; json(body: unknown): void };

// Unauthenticated on purpose: a load balancer polls it and it says nothing about anybody.
export async function health(_req: Req, res: Res) {
  res.status(200).json({ ok: healthOf() });
}

export async function ownerProfile(req: Req, res: Res) {
  const profile = await archive.profileOf(req.params.owner);
  if (!(await archive.canViewProfile(req, profile))) {
    res.status(403).json({ error: "forbidden" });
    return;
  }
  res.status(200).json({ profile });
}
