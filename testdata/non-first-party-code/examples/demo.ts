import express from "express";

const app = express();
const exampleKey = "AKIAIOSFODNN7EXAMPLE";

app.get("/example", (_req, res) => res.send(exampleKey));

export function exampleInputNotReached(req: { query: { value: string } }) {
  return req.query.value;
}
