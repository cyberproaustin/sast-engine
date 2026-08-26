import express from "express";

const app = express();
const nestedPackageKey = "AKIAIOSFODNN7EXAMPLE";

app.get("/nested-package", (_req, res) => res.send(nestedPackageKey));
