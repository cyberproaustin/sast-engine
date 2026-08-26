// Negative: a redirect the handler was HANDED rather than one it built.
//
// Written to look exactly like the positive -- one branch keeps what the call returns and
// the other does not -- because the difference is not in the shape. `res.redirect` has
// already answered the request by the time it returns, so whether the caller kept the
// value says nothing at all, and a rule that read only the word `redirect` would report
// the ordinary spelling of every Express login in existence.
type Req = { body: { password?: string } };
type Res = { redirect(to: string): void };

export function login(req: Req, res: Res) {
  if (!req.body.password) {
    return res.redirect("/login?error=missing");
  }
  res.redirect("/dashboard");
}
