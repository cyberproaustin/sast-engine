const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const express = require("express");

const app = express();

// POSITIVE. In the repository, in every clone of it, and in the history after somebody
// changes it.
const db = mysql.createConnection({
  host: "db.internal",
  user: "app",
  password: "hunter2",
});

// NEGATIVE. Read from the environment, which is not a literal and never matches.
const replica = mysql.createConnection({
  host: "replica.internal",
  user: "app",
  password: process.env.DB_PASSWORD,
});

app.get("/whoami", (req, res) => {
  // NEGATIVE, and it was a positive until the corpus said otherwise. Decoding a token
  // to LOOK at it is ordinary -- reading the issuer to choose a key, reading the expiry
  // -- and 58 sites across twenty-eight clean repositories do exactly that. The defect
  // is trusting the claims afterwards, which this call does not carry.
  const claims = jwt.decode(req.headers.authorization);
  res.json({ user: claims.sub });
});

app.get("/whoami-verified", (req, res) => {
  // NEGATIVE. verify() checks the signature before returning anything.
  const claims = jwt.verify(req.headers.authorization, process.env.JWT_KEY);
  res.json({ user: claims.sub });
});

module.exports = { app, db, replica };
