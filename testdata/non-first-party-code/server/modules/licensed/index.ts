import express from "express";

const app = express();
const licensedPackageKey = "AKIAIOSFODNN7EXAMPLE";

app.get("/licensed-package", (_req, res) => res.send(licensedPackageKey));
