// Anchored means the engine tied a finding to the surface it enumerated. Several kinds
// assert it by construction, on the sound reasoning that a weak key in a file nothing
// routes to is still a weak key -- but "nothing routes to it" and "nothing can run it"
// are different facts, and the second one was never asked.
//
// This module is the process entry. Everything it names, directly or through what those
// name, can run.
import express from "express";
import { previewUrl } from "./lib/preview.ts";

const app = express();

app.get("/preview", (req, res) => {
  res.json({ url: previewUrl(req.query.id as string) });
});

app.listen(3000);
