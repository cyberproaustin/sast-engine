import express from "express";
import { serveSnapshot } from "./snapshots";
import { health, ownerProfile } from "./status";
import { mutateDocument } from "./documents";
import { search } from "./search";
import { StatusConsumer } from "./broadcast";
import { ExportViews } from "./exports";

const app = express();

app.get("/:owner/:slug", serveSnapshot);
app.get("/:owner/s/:snapshotId", serveSnapshot);

// The negative that matters: a route with no control mounted next to one that has its own.
// The author meant this. Nothing they share says otherwise.
app.get("/healthz", health);
app.get("/:owner/profile", ownerProfile);

app.put("/documents/:id", mutateDocument);
app.get("/search", search);

// The socket consumer and the export views are plumbing rather than routes, and they are
// named here so the engine can see that the application runs them.
export const consumer = new StatusConsumer();
export const exports = new ExportViews();

export default app;
