// NEGATIVE, and the noise boundary. A function called `key` is an ordinary thing to
// write and says nothing on its own -- what makes one a bucket key is the limiter beside
// it. This module builds no limiter, so the identical header read is not claimed.
export const auditEntry = {
  key: (headers: Headers) => `audit:${headers.get("X-Forwarded-For") ?? "unknown"}`,
};
