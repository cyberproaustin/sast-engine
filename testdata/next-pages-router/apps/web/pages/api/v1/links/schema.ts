// NEGATIVE -- under `pages/api` and not a route. Next.js serves the DEFAULT export of a
// file in this directory; a module of named helpers is imported by the handlers beside
// it and is reachable from no URL at all.

export interface LinkInput {
  url: string;
  collection?: string;
}

export function isLinkInput(value: unknown): value is LinkInput {
  return typeof value === "object" && value !== null && "url" in value;
}
