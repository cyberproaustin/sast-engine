export function requireAuth(req, res, next): void {
  if (!req.headers.authorization) {
    res.status(401).send("unauthorized");
    return;
  }
  req.user = { id: "u1" };
  next();
}
