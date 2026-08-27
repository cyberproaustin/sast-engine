// A claim the caller made is the field, not the record it was filed in.
//
// `/promote` decides on the claim: the branch that runs is the one the caller asked for.
// `/scope` puts the same kind of field into a record and hands the record on, and the
// helper's opening null check tests the record. Nothing there reads a claim, and the
// object goes wherever the record goes -- which in a real application is a long way from
// the handler, in a module that has never heard of a request.
const express = require("express");

const app = express();

app.post("/promote", (req, res) => {
  if (req.body.role === "admin") {
    res.send("promoted");
    return;
  }
  res.status(403).send("denied");
});

function persist(record) {
  // The record is not the scope. This is the shape a presence check takes everywhere.
  if (record === undefined) {
    return "nothing to save";
  }
  return "saved";
}

app.post("/scope", (req, res) => {
  res.send(persist({ id: 1, scope: req.body.scope }));
});

app.listen(3000);
