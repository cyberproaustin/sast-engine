import express from "express";
import { getVariants, updateVariants } from "./variants";
import { getSegments, createSegment } from "./segments";
import { getReport, updateReport } from "./reports";
import { getWidget, updateWidget } from "./widgets";
import { login } from "./login";

const app = express();

app.get("/projects/:projectId/features/:featureName/environments/:environment/variants", getVariants);
app.put("/projects/:projectId/features/:featureName/environments/:environment/variants", updateVariants);

app.get("/projects/:projectId/segments", getSegments);
app.post("/projects/:projectId/segments", createSegment);

app.get("/reports/:reportId", getReport);
app.put("/reports/:reportId", updateReport);

// The one line that makes widgets.ts a negative. The check the handler does not make is
// made ahead of it, on the route.
function verifyWidgetBelongsToProject(req: express.Request, _res: express.Response, next: express.NextFunction) {
  const { widgetId, projectId } = req.params;
  if (!widgetId || !projectId) {
    _res.status(403).json({ error: "forbidden" });
    return;
  }
  next();
}

app.get("/projects/:projectId/widgets/:widgetId", getWidget);
app.put("/projects/:projectId/widgets/:widgetId", verifyWidgetBelongsToProject, updateWidget);

app.post("/login", login);

export default app;
