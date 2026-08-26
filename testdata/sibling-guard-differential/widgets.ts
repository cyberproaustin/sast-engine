// Negative: the check the write path is missing is applied before it runs.
//
// `deleteWidget` is the positive's shape exactly -- same two route values, same
// collaborator, no check in the body. What is different is one line in app.ts, where the
// route carries `requireWidgetAccess`. A guard that runs before the handler is a guard,
// and the handler's own body is the wrong place to look for it.
import { featureService } from "./service";

type Req = { params: Record<string, string>; body: unknown };
type Res = { status(code: number): Res; json(body: unknown): void };

export async function getWidget(req: Req, res: Res) {
  const { widgetId, projectId } = req.params;
  await featureService.validateWidgetBelongsToProject({ widgetId, projectId });
  const widget = await featureService.readWidget(widgetId);
  res.status(200).json({ widget });
}

export async function updateWidget(req: Req, res: Res) {
  const { widgetId, projectId } = req.params;
  await featureService.saveWidget(widgetId, projectId, req.body);
  res.status(200).json({ ok: true });
}
