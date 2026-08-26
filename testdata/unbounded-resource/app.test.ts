// A fixture is not an attack surface. Every route here is the first route in app.ts, and
// the rules say nothing about any of them -- said in the rules themselves rather than
// left to be filtered downstream, where a finding is still counted.
import express from "express";

import { sessionByToken } from "./store";

const app = express();

app.post("/sessions", (req, res) => {
  sessionByToken[req.body.token] = { at: Date.now() };
  res.json({ ok: true });
});

app.post("/import", (req, res) => {
  const parse = new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;

    req.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
      total += chunk.length;
      if (total > 1000000) {
        reject(new Error("Payload Too Large"));
      }
    });

    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });

  parse.then(() => res.json({ ok: true })).catch(() => res.status(413).send());
});

export default app;
