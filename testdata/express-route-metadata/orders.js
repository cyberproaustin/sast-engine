const { execSync } = require("node:child_process");

// POSITIVE. Reachable at GET /api/v2/orders/:id -- the router's mount prefix is half of
// that address, and the route is anchored to THIS function rather than to the apiAuth
// middleware registered in front of it.
exports.showOrder = function showOrder(req, res) {
  execSync(`order-report ${req.params.id}`);
  res.send("ok");
};

// NEGATIVE. Registered through a `.route(path)` chain, and reads nothing a caller sent.
exports.listThings = function listThings(req, res) {
  res.json([{ id: 1 }]);
};

// POSITIVE. The chain's path lives on the `.route()` call, so a model that only read the
// verb call's own first argument recorded this at `*` and the body it reads at nothing.
exports.createThing = function createThing(req, res) {
  execSync(`create-thing ${req.body.name}`);
  res.json({ ok: true });
};
