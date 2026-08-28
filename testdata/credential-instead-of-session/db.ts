// The record store, declared rather than implemented: what the engine reads is the SHAPE
// of the query -- a selection filed under `where` -- not what a client does at runtime.
export declare const prisma: {
  recipient: {
    findFirst(args: { where: Record<string, unknown> }): Promise<{ id: number; envelopeId: number } | null>;
    findFirstOrThrow(args: { where: Record<string, unknown> }): Promise<{ id: number; envelopeId: number }>;
  };
  document: {
    findFirst(args: { where: Record<string, unknown> }): Promise<{ id: string; ownerId: string } | null>;
    findMany(args: { where: Record<string, unknown> }): Promise<Array<{ id: string }>>;
    update(args: { where: Record<string, unknown>; data: Record<string, unknown> }): Promise<{ id: string }>;
    delete(args: { where: Record<string, unknown> }): Promise<{ id: string }>;
  };
  apiToken: {
    findFirst(args: { where: Record<string, unknown> }): Promise<{ id: number; token: string } | null>;
    delete(args: { where: Record<string, unknown> }): Promise<{ id: number }>;
  };
};
