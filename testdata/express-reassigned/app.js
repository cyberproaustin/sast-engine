const express = require("express");
const db = require("./db");

const app = express();

app.post("/buy", (req, res) => {
  // POSITIVE, and the shape is the whole point: a name declared with one value and
  // given another later. `var cart = null;` followed by `cart = {...}` inside a try is
  // ordinary JavaScript, and the second statement used to produce nothing at all --
  // an `=` is not one of the operators the expression lowering reads, so neither side
  // was visited and the value never reached the name.
  var cart = null;
  try {
    cart = { mail: req.body.mail, next: req.body.next };
  } catch (err) {
    return res.status(400).end();
  }
  finish(cart, res);
});

// The handler got long, so the response object was passed along. A channel that asks
// "is this the entry point's second parameter" used to stop at the call boundary and
// answer no, which meant nothing written here was a response at all.
function finish(cart, res) {
  db.one("INSERT INTO purchases(mail) VALUES('" + cart.mail + "');");
  res.redirect(cart.next);
}

app.listen(3000);
