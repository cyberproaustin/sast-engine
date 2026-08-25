import type { Request, Response, NextFunction } from "express";

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!(req as any).session?.userId) return res.status(401).end();
  next();
}

export function csrfProtection(req: Request, res: Response, next: NextFunction) {
  if (req.body._csrf !== (req as any).session?.csrfToken) return res.status(403).end();
  next();
}
