const jwt = require("jsonwebtoken");

// POSITIVE. The author configured neighbouring server options, but an absent deployment
// secret selects a value everybody with the source already knows.
const server = {
  port: 3000,
  secret: process.env.SESSION_SECRET || "super-secret",
};

function issue(userId) {
  // POSITIVE. Every possible home for the expiry is visible: the inline payload has no
  // exp claim and there is no options argument carrying expiresIn.
  return jwt.sign({ sub: userId, issuer: "fixture" }, server.secret);
}

function issueWithClaim(userId) {
  // NEGATIVE. The payload carries the expiry itself.
  return jwt.sign({ sub: userId, exp: 2000000000 }, server.secret);
}

function issueWithOptions(userId) {
  // NEGATIVE. The options carry the expiry.
  return jwt.sign({ sub: userId }, server.secret, { expiresIn: "15m" });
}

function issueUnknown(payload) {
  // NEGATIVE. The payload was assembled elsewhere, so absence of exp is unknowable.
  return jwt.sign(payload, server.secret);
}

module.exports = { issue, issueWithClaim, issueWithOptions, issueUnknown };
