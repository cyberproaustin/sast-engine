// The base class every controller in the application extends. Its `get`/`post` are the
// registration spelling the frontend was missing: one hop from a route description, with
// the wrapper's own parameters forwarded into it.

interface RouteOptions {
  method: string;
  path: string;
  handler: (req: never, res: never) => void;
  permission?: string;
}

const table: RouteOptions[] = [];

export default class Controller {
  route(options: RouteOptions): void {
    table.push(options);
  }

  get(path: string, handler: (req: never, res: never) => void, permission = "none"): void {
    this.route({ method: "get", path, handler, permission });
  }

  post(path: string, handler: (req: never, res: never) => void, permission = "none"): void {
    this.route({ method: "post", path, handler, permission });
  }

  // NEGATIVE — a wrapper that describes TWO routes is doing something a single row
  // cannot state, and picking one of them would be a guess.
  both(path: string, handler: (req: never, res: never) => void): void {
    this.route({ method: "get", path, handler });
    this.route({ method: "post", path, handler });
  }
}
