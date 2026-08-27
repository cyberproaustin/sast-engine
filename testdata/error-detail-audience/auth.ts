import type { Request, Response } from "express";

// The shape linkwarden writes on the first line of every API route it serves: a
// function the application defines itself, called by name, that resolves the session and
// answers the request when there is none. It resolves to a local function and carries no
// external symbol, which is the reason control detection could not see it.
export async function verifyUser(req: Request, res: Response): Promise<{ id: number }> {
  const header = req.headers.authorization;
  if (!header) {
    res.status(401).json({ error: "unauthorized" });
    throw new Error("unauthorized");
  }
  return { id: 1 };
}
