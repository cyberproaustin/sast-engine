// A complete key is still a key when it is written down. The banner-only negatives
// below are format tests; these bytes are the material the format says follows.
export const signingKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIObtRo8tkUqoMjeHhsOh2ouPpXCgBcP0EDoeuazrxsK9oAoGCCqGSM49
-----END EC PRIVATE KEY-----`;

export function migrate(privateKey: string): boolean {
  // EXPECTED CLEAN. This is the production misskey shape: the literal identifies a
  // serialisation format and the key being inspected came from somewhere else.
  if (privateKey.includes("-----BEGIN RSA PRIVATE KEY-----")) return true;

  // EXPECTED CLEAN. A direct comparison is the same recognition role. Limiting this
  // silence to a banner preserves ordinary caller-versus-credential authentication.
  return privateKey === "-----BEGIN OPENSSH PRIVATE KEY-----";
}
