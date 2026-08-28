// A caller who picks one of the destinations a deployment registered has not picked a
// destination. Every handler here carries `req.query.to` into `res.redirect`, so the
// dataflow is identical across all of them and only the DECISION in between differs.
//
// What clears a flow is three facts meeting: the callee settles its answer on an EQUALITY
// between the value (or the part of it a redirect turns on -- its origin) and data the
// program holds, the sink or the assignment sits on the branch that equality selected, and
// nothing else defines the value. Take any one of them away and the finding stands, which
// is what the positives below hold one at a time.
//
// Known limit, deliberately not papered over: the allow-list a caller sends IN THE REQUEST
// is recognised (see /caller-supplies-the-list), because the engine followed every read.
// One passed through a call whose body is not in the tree would not be, for the same
// reason medplum's configuration lookup is credited -- there is nothing to read.
import express from "express";

const app = express();

// The deployment's own registrations. Nothing a caller sends reaches this array.
const REGISTERED = ["https://app.example.com/done", "https://portal.example.com/done"];
const PARTNERS = [{ site: "https://partner.example.com/" }];

function isRegisteredRedirect(candidate: string): boolean {
  for (const uri of REGISTERED) {
    if (uri === candidate) {
      return true;
    }
  }
  return false;
}

function isPartnerSite(candidate: string): boolean {
  const asked = new URL(candidate);
  return PARTNERS.some((partner) => {
    const known = new URL(partner.site);
    return asked.hostname === known.hostname && asked.protocol === known.protocol;
  });
}

// Only the PATH is pinned. Every host in the world spells `/done` the same way, so this
// says nothing about where the browser is sent.
function hasKnownPath(candidate: string): boolean {
  const asked = new URL(candidate);
  return PARTNERS.some((partner) => new URL(partner.site).pathname === asked.pathname);
}

// Looks at the value and never decides anything about it.
function observeRedirect(candidate: string): boolean {
  console.log("redirect requested", candidate);
  return candidate.length > 0;
}

function isOneOf(list: string[], candidate: string): boolean {
  for (const item of list) {
    if (item === candidate) {
      return true;
    }
  }
  return false;
}

function sameOrigin(a: string, b: string): boolean {
  return new URL(a).origin === new URL(b).origin;
}

// Answers with a registered URI, with the requested one, or with nothing -- and with the
// requested one only inside the branch that proved it shares an origin with a registered
// one. Whatever a caller of this does with the answer, the answer is a destination the
// deployment registered.
function resolveRegistered(requested: string, allowPartial: boolean): string | undefined {
  for (const uri of REGISTERED) {
    if (uri === requested) {
      return uri;
    }
    if (allowPartial && sameOrigin(uri, requested)) {
      return requested;
    }
  }
  return undefined;
}

app.get("/exact", (req, res) => {
  const to = req.query.to as string;
  // NEGATIVE. The redirect is reachable only from the branch where the value equalled a
  // registered string, whole.
  if (!isRegisteredRedirect(to)) return res.status(400).send("unknown destination");
  return res.redirect(to);
});

app.get("/branch", (req, res) => {
  const to = req.query.to as string;
  let destination = "/account";
  // NEGATIVE. Both arms rejoin, so the sink is not on the approved branch and never can
  // be. The ASSIGNMENT is, and it is the only one that carries the caller's value.
  if (isRegisteredRedirect(to)) {
    destination = to;
  }
  return res.redirect(destination);
});

app.get("/origin", (req, res) => {
  const to = req.query.to as string;
  // NEGATIVE. The whole string is not pinned and does not need to be: CWE-601 asks who
  // chose the site, and the host is a partner's.
  if (!isPartnerSite(to)) return res.status(400).send("unknown destination");
  return res.redirect(to);
});

app.get("/resolved", (req, res) => {
  const to = req.query.to as string;
  // NEGATIVE. No guard here at all. What constrains the value is what the function it
  // came out of can answer with.
  const target = resolveRegistered(to, false);
  return res.redirect(target ?? "/account");
});

app.get("/named", (req, res) => {
  const to = req.query.to as string;
  // NEGATIVE. The same decision as /exact, with the answer given a name one statement
  // first. A name is not an operation: nothing happens between the call and the test that
  // could change what the test is about.
  const registered = resolveRegistered(to, false);
  if (!registered) return res.status(400).send("unknown destination");
  return res.redirect(to);
});

app.get("/unchecked", (req, res) => {
  const to = req.query.to as string;
  // POSITIVE. The same value at the same sink with nothing asked about it.
  return res.redirect(to);
});

app.get("/dropped", (req, res) => {
  const to = req.query.to as string;
  // POSITIVE. The question is asked and the answer is thrown away, so nothing follows
  // from it. This is the case a rule keyed on "was a validator called" gets wrong.
  isRegisteredRedirect(to);
  return res.redirect(to);
});

app.get("/reversed", (req, res) => {
  const to = req.query.to as string;
  // POSITIVE. Registered destinations are the ones that leave, so the redirect is
  // reachable exactly from the branch where the answer was NO. The graph is identical to
  // /exact and only the polarity differs.
  if (isRegisteredRedirect(to)) return res.status(400).send("already visited");
  return res.redirect(to);
});

app.get("/observed", (req, res) => {
  const to = req.query.to as string;
  // POSITIVE. The guard's shape is exactly /exact's. The function inside it logs the
  // value and measures it, and measuring is not comparing: nothing here says the value
  // is one of anything.
  if (!observeRedirect(to)) return res.status(400).send("empty destination");
  return res.redirect(to);
});

app.get("/path-only", (req, res) => {
  const to = req.query.to as string;
  // POSITIVE. A real equality against real configuration, on the one part of a URL that
  // does not decide where the browser goes.
  if (!hasKnownPath(to)) return res.status(400).send("unknown destination");
  return res.redirect(to);
});

app.get("/redefined", (req, res) => {
  const to = req.query.to as string;
  let destination = "/account";
  // POSITIVE. The approved assignment is there, and so is a second one nothing decided.
  // A witness path shows one definition; the other is what makes the value the caller's.
  if (isRegisteredRedirect(to)) {
    destination = to;
  }
  if (req.query.force) {
    destination = to;
  }
  return res.redirect(destination);
});

app.get("/named-twice", (req, res) => {
  const to = req.query.to as string;
  let registered = resolveRegistered(to, false);
  if (req.query.force) {
    registered = to;
  }
  // POSITIVE. The name holds two things now, and the second is the caller's own string.
  // A truthy answer here means "not empty" as readily as it means "registered", so the
  // test is no longer about what the call decided.
  if (!registered) return res.status(400).send("unknown destination");
  return res.redirect(to);
});

app.get("/caller-supplies-the-list", (req, res) => {
  const to = req.query.to as string;
  const allowed = req.body.allowed as string[];
  // POSITIVE. Equality, a collection, a guard, the right polarity -- and the collection
  // came out of the same request as the value. Matching a caller's string against a
  // caller's list decides nothing.
  if (!isOneOf(allowed, to)) return res.status(400).send("unknown destination");
  return res.redirect(to);
});

export default app;
