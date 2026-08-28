import { prisma } from "./db.ts";

/**
 * The lookup one hop below the handler, which is where documenso puts every one of them:
 * the route reads the token out of the request and hands it to a server-only function
 * whose first statement resolves the recipient from it. A fact that stopped at the
 * handler body would miss four of documenso's five and see only the fifth.
 */
export async function signFieldWithToken({ token, value }: { token: string; value: string }) {
  const recipient = await prisma.recipient.findFirstOrThrow({ where: { token } });
  return { recipientId: recipient.id, value };
}

/**
 * The near miss at the SAME hop. `tokenId` is the primary key of the row a token is
 * stored in, and a caller can count through primary keys; nothing here proves the caller
 * held anything. This route must keep reporting.
 */
export async function revokeApiTokenById({ tokenId }: { tokenId: string }) {
  const record = await prisma.apiToken.findFirst({ where: { id: tokenId } });
  if (!record) {
    return { revoked: false };
  }
  await prisma.apiToken.delete({ where: { id: record.id } });
  return { revoked: true };
}

/**
 * A stated miss that closed, kept here because the widening it guarded against happened.
 * The token arrives as a bare positional argument, and binding by position was excluded:
 * a position did not survive a receiver, since Python declares `self` and `cls` as
 * parameter zero at a call site that writes neither, and bound by position saleor's
 * `setPassword` cited `User.objects.get(email=email)` as a selection keyed by the caller's
 * password. The frontend now says which parameter each argument becomes, so this is read.
 */
export async function completeByToken(token: string) {
  const recipient = await prisma.recipient.findFirstOrThrow({ where: { token } });
  return { recipientId: recipient.id };
}
