import express from "express";

const app = express();

app.get("/json-object", (req, reply) => {
  // Fastify and Express both serialize an object; these bytes are JSON, not markup.
  reply.send({ error: req.query.message });
});

app.get("/html", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<p>${req.query.message}</p>`);
});

app.get("/sandboxed", (req, res) => {
  res.setHeader("Content-Security-Policy", "sandbox");
  res.send(`<p>${req.query.message}</p>`);
});

app.get("/plain", (req, res) => {
  res.send(`<p>${req.query.message}</p>`);
});

app.get("/text", (req, res) => {
  res.setHeader("Content-Type", "text/plain");
  res.send(`<p>${req.query.message}</p>`);
});

app.get("/stringified", (req, res) => {
  res.send(JSON.stringify({ message: req.query.message }));
});

export default app;
