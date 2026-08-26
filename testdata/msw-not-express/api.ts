// One module, both things. A file is entitled to mock one API and serve another, so the
// exclusion is per IDENTIFIER: `http` came from the mock library and `app` did not.
import express from "express";
import { http, HttpResponse } from "msw";

export const app = express();

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

export const handlers = [http.get("/api/meta", () => HttpResponse.json({ version: "1" }))];
