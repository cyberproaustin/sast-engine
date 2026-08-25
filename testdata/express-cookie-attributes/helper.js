// Options built somewhere else. The point of this file is that the call site cannot
// see what it returns.
function getCookieOpts() {
  return { httpOnly: true, secure: true, sameSite: "lax" };
}

module.exports = { getCookieOpts };
