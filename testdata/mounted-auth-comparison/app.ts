import { Router } from "express";
import { getAuthenticatedContext } from "./context";

const root = Router();

// The author made this router public. Routes registered here are comparable with one
// another, not with a protected router that happens to be declared in the same module.
const publicRoutes = Router();
root.use(publicRoutes);
publicRoutes.get("/metadata", (_req, res) => res.json({ resourceType: "CapabilityStatement" }));
publicRoutes.get("/$versions", (_req, res) => res.json({ versions: ["4.0"] }));

const protectedRoutes = Router();
root.use(protectedRoutes);

protectedRoutes.get("/Patient", (_req, res) => {
  const ctx = getAuthenticatedContext();
  res.json(ctx.search("Patient"));
});

protectedRoutes.get("/Observation", (_req, res) => {
  const ctx = getAuthenticatedContext();
  res.json(ctx.search("Observation"));
});

protectedRoutes.get("/Encounter", (_req, res) => {
  const ctx = getAuthenticatedContext();
  res.json(ctx.search("Encounter"));
});

// EXPECTED DEVIATION. Unlike the public metadata routes, this handler shares the mount
// whose other routes all establish an authenticated context, and it alone does not.
protectedRoutes.get("/Medication", (_req, res) => {
  res.json(loadMedication());
});

function loadMedication() {
  return [];
}
