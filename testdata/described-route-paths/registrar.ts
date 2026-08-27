interface RouteOptions {
  method: string;
  path: string;
  handler: (req: never, res: never) => void;
}

// The framework walks the table at startup. Nothing calls anything until then, which is
// why the description is the only evidence a route exists at all.
const table: RouteOptions[] = [];

export function register(options: RouteOptions): void {
  table.push(options);
}
