const db = require("./db");

// A middleware FACTORY: the handler is what calling this returns. Express applications
// are written this way constantly, and it is how OWASP Juice Shop registers its API.
function login() {
  return (req, res) => {
    // POSITIVE. `|| ''` is the most common way code writes a default, and the caller's
    // value is what survives it whenever one was sent.
    db.sequelize.query(
      `SELECT * FROM Users WHERE email = '${req.body.email || ""}' AND deleted IS NULL`,
    );
    res.json({ ok: true });
  };
}

// NEGATIVE. A factory that returns one of two handlers cannot be resolved to either,
// and the engine says nothing rather than picking one.
function ambiguous(flag) {
  if (flag) {
    return (req, res) => res.json({ a: req.query.x });
  }
  return (req, res) => res.json({ b: req.query.y });
}

module.exports = { login, ambiguous };
