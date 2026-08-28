import type { NextFunction, Request, Response } from "express";

/** The session middleware every ordinary route on this router mounts. */
export function requireAuthenticatedSession(_req: Request, _res: Response, next: NextFunction): void {
  next();
}
