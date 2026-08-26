// The four ways a route that WAS found can still be wrong about itself.
//
// A registration states a verb, a framework, a path and a handler. Three of those were
// being reported from the wrong place: a configured base path printed as `*`, a router's
// mount prefix dropped, and the entry anchored to whichever argument this frontend could
// resolve rather than to the one the framework calls last.
const express = require("express");
// A middleware factory from a package outside the tree. What it returns is the handler,
// and nothing here can resolve it -- which is the whole point.
const prometheusMetrics = require("prometheus-api-metrics");

const { apiAuth } = require("./auth");
const { showOrder, listThings, createThing } = require("./orders");

const app = express();

// The base path an operator configures. Its default is the address of every deployment
// that leaves the variable alone; the alternative was `*`, which says this route answers
// every request in the application.
const basePath = process.env.BASE_PATH || "";

// A router mounted UNDER a prefix. Every route registered on it below is served at
// `/api/v2/...`, and a path recorded without the prefix names an address that answers
// nothing.
const api = express.Router();
app.use(`${basePath}/api/v2`, api);

api.get("/orders/:id", apiAuth, showOrder);

// The handler is the argument passed LAST, whether or not it can be resolved. Looking
// for the last RESOLVABLE argument instead walked back past this factory call and
// anchored the route to its authentication middleware -- so the surface said the handler
// of /metrics was the auth check, which is a false statement about the one function every
// judgement about this route is made against.
app.get("/metrics", apiAuth, prometheusMetrics());

// A verb call in a `.route(path)` chain carries no path of its own: its first argument is
// already the handler. Every route registered this way used to record its path as `*`.
api.route("/things").get(listThings).post(createThing);

// A prefix that genuinely cannot be read. Marked unresolved and NAMED, so an operator can
// look up the expression that stood in the way.
app.get(`${runtimePrefix()}/callback`, (req, res) => res.send("ok"));

function runtimePrefix() {
  return "/" + Math.random().toString(36).slice(2);
}

module.exports = app;
