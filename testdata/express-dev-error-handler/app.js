const express = require("express");
const errorhandler = require("errorhandler");

const app = express();

app.get("/thing/:id", (req, res) => {
  res.json({ id: req.params.id });
});

// POSITIVE. This middleware exists to print a stack trace to the browser, and its own
// documentation says to use it in development only. The NODE_ENV guard around it is a
// deployment fact rather than a property of the source: the middleware is in the bundle
// either way, and what a scanner can say is that the application is one environment
// variable away from serving its internals.
if (app.get("env") === "development") {
  app.use(errorhandler());
}

// NEGATIVE. The production handler, which answers with a status and nothing else.
app.use((err, req, res, _next) => {
  res.status(err.status || 500).json({ error: "internal error" });
});

app.listen(3000);
