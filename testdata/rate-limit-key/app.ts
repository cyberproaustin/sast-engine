/**
 * A default IP bucket is only as trustworthy as Express's proxy configuration.
 *
 * The positive disables express-rate-limit's validation and leaves keyGenerator absent
 * while trusting every forwarded hop, so a caller can choose the req.ip bucket. The
 * second limiter supplies its own key and is the shape that must stay silent.
 */
import express from "express";
import rateLimit from "express-rate-limit";

const app = express();
app.set("trust proxy", true);

app.use(rateLimit({
  windowMs: 60_000,
  limit: 10,
  validate: false,
}));

app.post("/login", (_req, res) => res.send("ok"));

const keyed = express();
keyed.use(rateLimit({
  windowMs: 60_000,
  limit: 10,
  validate: false,
  keyGenerator: (req) => req.get("X-Account-ID") || "anonymous",
}));
keyed.get("/account", (_req, res) => res.send("ok"));
