// Authentication middleware. It is a control on the routes it is bound to, and it is
// never the handler of any of them.
exports.apiAuth = function apiAuth(req, res, next) {
  if (!req.headers.authorization) {
    res.status(401).send("unauthorized");
    return;
  }
  next();
};
