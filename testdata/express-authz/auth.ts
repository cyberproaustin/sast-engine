// In-house middleware. Nothing recognizes these names by default, and convention
// analysis does not need to: what matters is that peers share them.

export function requireAuth(req, res, next): void {
  if (!req.headers.authorization) {
    res.status(401).send("unauthorized");
    return;
  }
  next();
}

export function requireAdmin(req, res, next): void {
  if (req.user?.role !== "admin") {
    res.status(403).send("forbidden");
    return;
  }
  next();
}
