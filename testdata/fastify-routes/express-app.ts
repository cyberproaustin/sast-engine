import express from "express";

// The negative. Two frameworks in one tree is the ordinary case -- a Fastify backend
// with an Express admin panel beside it -- and each route has to carry the label of the
// server it was registered on, because that is what selects the request shape.
const app = express();

app.get("/legacy/health", (req, res) => {
  res.send("ok");
});

export default app;
