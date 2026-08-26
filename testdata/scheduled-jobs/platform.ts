/**
 * The parts of the platform this corpus stands on, declared rather than implemented.
 *
 * Ambient on purpose, for the same reason `second-order-taint` declares its store: a stub
 * with a body resolves, and a resolved call visibly returns what it was handed, which is
 * the one case the engine was already right about. A real cron library, a real ORM client
 * and a real event bus are all calls the frontend cannot read into.
 */
type Row = Record<string, string>;

type Table = {
  create(args: unknown): Promise<Row>;
  findFirst(args?: unknown): Promise<Row>;
  findMany(args?: unknown): Promise<Row[]>;
};

declare const db: {
  job: Table;
  webhook: Table;
  setting: Table;
};

declare const sql: {
  query(text: string): Promise<unknown>;
};

/** croner: the schedule IS the constructor. */
declare class Cron {
  constructor(pattern: string, handler: () => void);
  constructor(pattern: string, options: unknown, handler: () => void);
}

/** The node event bus, named as the language names it. */
declare class EventEmitter {
  on(event: string, listener: (payload: Row) => void): this;
  emit(event: string, payload: Row): boolean;
}

/** A socket. The same three-letter method, and a REMOTE caller on the other end. */
declare class Socket {
  on(event: string, listener: (payload: Row) => void): this;
}

/** A calendar. `schedule` here books a meeting; nothing runs. */
declare const planner: {
  schedule(from: string, to: string): void;
};

declare const scheduler: {
  schedule(job: () => Promise<void>, everyMs: number, name: string): void;
};

declare const bus: EventEmitter;
declare const socket: Socket;

export { bus, Cron, db, planner, scheduler, socket, sql };
