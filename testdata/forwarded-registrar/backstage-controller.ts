import Controller from "./controller.ts";

const IMPACT_PATH = "/impact/metrics";

// Three routes, none of which is spelled as a registration anywhere in this file. The
// unauthenticated metrics endpoint is the one that mattered: it was absent from the
// surface entirely, so nothing downstream could say it had no control on it.
export class BackstageController extends Controller {
  constructor() {
    super();
    this.get("/prometheus", async (_req, _res) => {});
    this.get(IMPACT_PATH, async (_req, _res) => {});
    this.post("/heap-snapshot", this.writeSnapshot, "admin");
    // NEGATIVE — ambiguous wrapper, so no row rather than a guessed one.
    this.both("/either", async (_req, _res) => {});
  }

  writeSnapshot(_req: never, _res: never): void {}
}
