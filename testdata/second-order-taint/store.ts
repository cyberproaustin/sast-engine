/**
 * A store, declared rather than implemented.
 *
 * Ambient on purpose. A stub with a body resolves, and a resolved getter visibly returns
 * what it was given -- which is the one case the engine was already right about. Every
 * defect and every silence in this corpus is about a call the frontend CANNOT read, which
 * is what a real ORM client, a real cache and a real session are.
 *
 * The models are properties of one client, which is how Prisma, TypeORM and Sequelize all
 * spell a table, and it is the spelling the store's NAME is read out of.
 */
type Row = Record<string, string>;

type Table = {
  create(args: unknown): Promise<Row>;
  update(args: unknown): Promise<Row>;
  findUnique(args?: unknown): Promise<Row>;
  findFirst(args?: unknown): Promise<Row>;
  findMany(args?: unknown): Promise<Row[]>;
};

declare const db: {
  note: Table;
  page: Table;
  audit: Table;
  profile: Table;
  tenant: Table;
};

declare const cache: Map<string, string>;

declare const sql: {
  query(text: string): Promise<unknown>;
};

export { cache, db, sql };
