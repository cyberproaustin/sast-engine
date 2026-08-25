const express = require("express");
const products = require("./products");

const app = express();

// POSITIVE. The handler is here and the injection is in another file, behind an export
// table -- `module.exports = { getProduct, search }` -- which is how most CommonJS code
// is written. Resolving the call is the whole of it: unresolved, the tainted argument
// taints the call's RESULT instead of the callee's parameter, and everything the callee
// does with it is invisible while the report still looks complete.
app.get("/product", (req, res) => {
  products.getProduct(req.query.id).then((row) => res.json(row));
});

// POSITIVE, and the reason a merge point needs a rule of its own. Both branches carry the
// caller's value; one goes through a numeric conversion, which clears a SQL context, and
// the other does not. The value is the same value either way, and the finding must rest on
// the branch that proves it -- the unconverted one.
app.get("/product-either", (req, res) => {
  const term = req.query.exact ? Number(req.query.id) : String(req.query.term);
  products.search(term).then((rows) => res.json(rows));
});

// NEGATIVE. Every branch converts, so nothing composable survives either way.
app.get("/product-safe", (req, res) => {
  const id = req.query.exact ? Number(req.query.id) : Number(req.query.other);
  products.getProduct(id).then((row) => res.json(row));
});

app.listen(3000);
