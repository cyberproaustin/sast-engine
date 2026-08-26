// The positive this corpus exists for: two handlers on one resource, one value out of one
// request, and only one of them asks whether the caller may have it.
//
// `featureName` and `projectId` both arrive in the route. Nothing relates them: a feature
// belongs to exactly one project, and a caller with permission on their own project can
// name a feature in somebody else's. The read path asks. The write path takes the same two
// values out of the same request and does not.
import { featureService } from "./service";

type Req = { params: Record<string, string>; body: unknown; user: { id: string } };
type Res = { status(code: number): Res; json(body: unknown): void };

export async function getVariants(req: Req, res: Res) {
  const { projectId, featureName, environment } = req.params;
  await featureService.validateFeatureBelongsToProject({ featureName, projectId });
  const variants = await featureService.readVariants(featureName, environment);
  res.status(200).json({ variants });
}

export async function updateVariants(req: Req, res: Res) {
  const { projectId, featureName, environment } = req.params;
  const variants = await featureService.saveVariants(
    featureName,
    projectId,
    environment,
    req.body,
    req.user,
  );
  res.status(200).json({ variants });
}
