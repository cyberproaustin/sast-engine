import express from "express";

const app = express();
const workspaceKey = "AKIAIOSFODNN7EXAMPLE";

app.get("/workspace", (_req, res) => res.send(workspaceKey));
