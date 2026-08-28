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
 * A STATED MISS, kept here so that widening the binding rule cannot pass unnoticed. The
 * token arrives as a bare positional argument, and an argument is bound to a parameter by
 * NAME only: a position does not survive a receiver, and Python declares `self` and `cls`
 * as parameter zero at a call site that writes neither. saleor's `setPassword` measured
 * what that costs -- bound by position, it came out citing `User.objects.get(email=email)`
 * as a selection keyed by the caller's password.
 */
export async function completeByToken(token: string) {
  const recipient = await prisma.recipient.findFirstOrThrow({ where: { token } });
  return { recipientId: recipient.id };
}
