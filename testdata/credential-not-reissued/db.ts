// A stand-in for the generated ORM client, so the fixture has a receiver to name.
type Row = { id: number };

type Model = {
  upsert(args: Record<string, unknown>): Promise<Row>;
  create(args: Record<string, unknown>): Promise<Row>;
  update(args: Record<string, unknown>): Promise<Row>;
};

export const prisma = {
  recipient: {} as Model,
  invitation: {} as Model,
  signer: {} as Model,
};
