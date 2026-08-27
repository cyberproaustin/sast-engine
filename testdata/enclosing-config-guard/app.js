const express = require("express");
const errorhandler = require("errorhandler");

const app = express();

if (process.env.NODE_ENV !== "production") {
  // Still reported: an unset or mistaken NODE_ENV reaches this branch in deployment.
  // The enclosing condition is why it informs rather than gates.
  app.use(errorhandler());
}

// No deployment condition qualifies this one, so it retains ordinary gating behavior.
app.use(errorhandler());

app.listen(3000);
