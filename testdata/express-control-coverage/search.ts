// The route that reaches filters.ts, so the restriction it builds is one an enumerated
// entry point actually depends on.
import { addAccessPolicyFilters } from "./filters";

type Req = { query: Record<string, string>; user: { policies: { resourceType: string; criteria?: string }[] } };
type Res = { status(code: number): Res; json(body: unknown): void };

export async function search(req: Req, res: Res) {
  const builder = { predicate: { expressions: [] as unknown[] } };
  addAccessPolicyFilters(builder, req.query.resourceType, req.user.policies);
  res.status(200).json({ predicate: builder.predicate });
}
