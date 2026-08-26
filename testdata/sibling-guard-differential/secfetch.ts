// The second positive, and the one that needs no sibling handler at all -- only a sibling
// BRANCH. `Response.redirect` builds a response and sends nothing, so a caller who does
// not return it has written a line that does not exist. The branch above returns the
// identical construction, which is how the program says what this one was meant to do.
type Req = { headers: { get(name: string): string | null }; url: string };

export function filterRequest(req: Req): Response | null {
  const mode = req.headers.get("sec-fetch-mode");
  if (mode !== "navigate" && mode !== "cors") {
    return Response.redirect("/", 302);
  }

  const site = req.headers.get("sec-fetch-site");
  if (site !== "same-origin" && site !== "none") {
    Response.redirect("/", 302);
  }

  return null;
}
