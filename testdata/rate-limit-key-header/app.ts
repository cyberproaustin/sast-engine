/**
 * The bucket key a caller writes, and the rule beside it that could not see one.
 *
 * `rate-limit-key` holds the configuration reading of this weakness: express-rate-limit's
 * default `req.ip` key, `app.set("trust proxy", true)`, and the library's own validation
 * switched off. Those three facts are one library's spelling of it, and unleash is where
 * the engine found it. reactive-resume has the identical weakness and none of the three
 * facts: it writes its own key, sets no Express trust anywhere, and limits with a package
 * whose name no constructor list had. Varying `X-Forwarded-For` gives a fresh bucket
 * either way.
 *
 * So this corpus states the KEY. The module builds a limiter, a function in it is that
 * limiter's key, and the key reaches a forwarding header.
 */
import { createRatelimitMiddleware } from "@orpc/experimental-ratelimit";
import { MemoryRatelimiter } from "@orpc/experimental-ratelimit/memory";

import { TRUSTED_IP_HEADERS } from "./headers";

type Context = { reqHeaders?: Headers; user?: { id: string } | null };

function getTrustedIp(headers?: Headers): string | null {
  if (!headers) return null;
  for (const headerName of TRUSTED_IP_HEADERS) {
    const raw = headers.get(headerName)?.trim();
    if (!raw) continue;
    // The FIRST element of the chain is the one the client appended, which is what makes
    // this wrong even where a proxy is real: a proxy appends, it does not replace.
    const ip = raw.split(",")[0]?.trim();
    if (ip) return ip;
  }
  return null;
}

function getClientKey(headers?: Headers): string {
  return `ip:${getTrustedIp(headers) ?? "unknown"}`;
}

function getUserKey(context: Context): string {
  return context.user?.id ?? "anon";
}

function getAccountKey(headers?: Headers): string {
  // A header the caller supplies too, and deliberately not claimed. A key naming an
  // ACCOUNT is a key the application means to trust, and whether it is authenticated is
  // a different question with a different answer.
  return `acct:${headers?.get("X-Account-ID") ?? "none"}`;
}

const loginLimiter = new MemoryRatelimiter({ maxRequests: 5, window: 600_000 });
const exportLimiter = new MemoryRatelimiter({ maxRequests: 5, window: 60_000 });
const accountLimiter = new MemoryRatelimiter({ maxRequests: 20, window: 60_000 });

// POSITIVE. The bucket key is read out of a forwarding header, so anyone can send a
// different one and land in a bucket of their own.
export const loginRateLimit = createRatelimitMiddleware<Context, { username: string }>({
  limiter: loginLimiter,
  key: ({ context }, input) => `login:${input.username}:${getClientKey(context.reqHeaders)}`,
});

// NEGATIVE. A key built from established identity. The caller does not choose who they
// are, so varying anything they send keeps them in the same bucket.
export const exportRateLimit = createRatelimitMiddleware<Context, { id: string }>({
  limiter: exportLimiter,
  key: ({ context }, input) => `export:${getUserKey(context)}:${input.id}`,
});

// NEGATIVE. A key from a header that is not a forwarding header. It is caller-supplied
// and the rule stays silent, because this rule is about believing a proxy's address and
// not about every value a request carries.
export const accountRateLimit = createRatelimitMiddleware<Context, unknown>({
  limiter: accountLimiter,
  key: ({ context }) => getAccountKey(context.reqHeaders),
});
