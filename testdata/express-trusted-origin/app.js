const dns = require("dns/promises");
const express = require("express");

const app = express();

app.post("/internal/reindex", (req, res) => {
  // POSITIVE. The Referer says where a request came from only in the sense that it says
  // whatever the sender wrote there: a browser sends it, a script omits it, and anything
  // at all can forge it.
  if (req.headers.referer === "https://admin.example.com/console") {
    return res.json({ started: true });
  }
  res.status(403).json({ error: "forbidden" });
});

app.get("/internal/status", (req, res) => {
  // NEGATIVE. The Referer used to build a link back is not a security decision.
  res.json({ back: req.headers.referer, ok: true });
});

app.get("/internal/peers", async (req, res) => {
  // POSITIVE. A reverse lookup returns whatever the owner of the ADDRESS block chose to
  // publish in the PTR record, which is not evidence of who they are.
  const name = await dns.reverse(req.socket.remoteAddress);
  if (name === "trusted.internal") {
    return res.json({ peers: ["a", "b"] });
  }
  res.status(403).json({ error: "forbidden" });
});

module.exports = app;
