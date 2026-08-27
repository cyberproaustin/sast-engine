// A helper answers the caller that asked it, not every caller that ever asked.
//
// `pick` is reached from two routes. `/report` hands it a request value in the position
// that comes back out. `/label` hands it a request value in a position that goes nowhere
// and a constant in the position that returns, so nothing a caller sent can leave that
// call -- and the second route is here because the first route's value used to leave
// through it. Sending a tainted return to every call site that had passed SOMETHING
// classified composed a chain out of two different frames: entered at one call, left at
// another the execution never made. The flow printed under `/label` then cited
// `req.query.title`, an expression that does not occur in that handler.
const express = require("express");

const app = express();

const HEADING = "Report";

function pick(value, label) {
  // `label` is measured and discarded. Only `value` comes back out.
  if (label.length > 64) {
    return HEADING;
  }
  return value;
}

function reportHandler(req, res) {
  // The request value enters `pick` here, and here is where it comes back.
  res.send(`<h1>${pick(req.query.title, "title")}</h1>`);
}

function labelHandler(req, res) {
  // The returning argument is written in this file. This call site passes something
  // caller-controlled -- the label -- and gets a constant back.
  res.send(`<h1>${pick(HEADING, req.query.label)}</h1>`);
}

app.get("/report", reportHandler);
app.get("/label", labelHandler);

app.listen(3000);
