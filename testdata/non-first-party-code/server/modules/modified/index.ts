// Original Source: https://github.com/example/published-package
import express from "express";

const app = express();
const modifiedPackageKey = "AKIAIOSFODNN7EXAMPLE";

app.get("/modified-package", (_req, res) => res.send(modifiedPackageKey));
