// Negative: two handlers whose guards differ, on values that are not the same value.
//
// The read validates the date range it was given. The write never reads a date range at
// all -- it shares `reportId` with the read and nothing else -- so the check the read
// performs is not a check the write skipped, it is a question about an argument the write
// does not have. The two paths differ, and the difference is about different things.
import { featureService } from "./service";

type Req = { params: Record<string, string>; query: Record<string, string>; body: unknown };
type Res = { status(code: number): Res; json(body: unknown): void };

export async function getReport(req: Req, res: Res) {
  const { reportId } = req.params;
  const { range } = req.query;
  await featureService.validateDateRange(range);
  const report = await featureService.readReport(reportId, range);
  res.status(200).json({ report });
}

export async function updateReport(req: Req, res: Res) {
  const { reportId } = req.params;
  await featureService.saveReport(reportId, req.body);
  res.status(200).json({ ok: true });
}
