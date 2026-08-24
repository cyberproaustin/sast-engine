// Middleware exposed as properties of an imported object — the shape most real
// Express apps use, and one that a literal-only detector misses entirely.
export default {
  required(req, res, next): void {
    if (!req.headers.authorization) {
      res.status(401).send("unauthorized");
      return;
    }
    next();
  },
  optional(req, res, next): void {
    next();
  },
};
