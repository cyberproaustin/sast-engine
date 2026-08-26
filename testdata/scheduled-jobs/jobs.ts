/**
 * Scheduled jobs and an event-bus consumer: code that runs with the application's
 * privileges and that no remote caller can reach.
 *
 * This is the class of entry point the engine had no name for. Every function below was
 * unreachable from anything enumerated, so the surface said the application had none of
 * this and every defect inside it was invisible -- not judged and found clean, but never
 * asked about at all, which is the failure ADR-009 exists to prevent.
 *
 * The trust label is the other half. A cron job is not an anonymous HTTP request: whoever
 * can make one run already has the process. Reporting the two at one rank would be a lie
 * in one direction or the other, so each entry point states who can trigger it and the
 * ranking follows from that rather than from the seriousness of what it does.
 */
import { bus, Cron, db, planner, scheduler, socket, sql } from "./platform";

// EXPECTED FINDING -- a nightly job reading a column a request wrote.
//
// This is the whole shape the class exists for. `POST /jobs` put a caller's text in
// `job.command` and went away; hours later a timer runs this over whatever is in the
// table. Request-scoped taint has nothing left to say by then, and the store model is
// what carries the fact across -- but only if something reaches this function, and until
// scheduled jobs were entry points nothing did.
new Cron("0 3 * * *", async () => {
  const job = await db.job.findFirst({ where: { state: "queued" } });
  await sql.query(`UPDATE job SET state = 'running' WHERE command = '${job.command}'`);
});

// EXPECTED FINDING -- the same shape through an interval rather than a cron expression.
//
// `setInterval` is a scheduler that ships with the language. The registration is a plain
// call and the callback is its first argument.
setInterval(async () => {
  const hook = await db.webhook.findFirst();
  await sql.query(`SELECT * FROM delivery WHERE target = '${hook.target}'`);
}, 60_000);

// EXPECTED FINDING -- an event-bus consumer.
//
// A bus delivers within the process, so the consumer runs on the server's own thread with
// no request around it. The receiver is an EventEmitter as the CHECKER sees it, which is
// what tells this apart from the socket below; the method name is the same three letters
// in both.
bus.on("job-finished", async () => {
  const job = await db.job.findFirst();
  await sql.query(`INSERT INTO history (command) VALUES ('${job.command}')`);
});

// A registration written as a TABLE of jobs, which is the shape uptime-kuma registers
// its background work with: a loop, a cron expression read off a property, and the
// callback read off another property of the same object.
//
// The callback is the LAST argument written as a reference rather than the first, and
// that is the whole of the selection rule. `job.interval` and `job.jobFunc` are the same
// syntax and only the position tells them apart; taking the first reference would have
// scheduled the cron expression and enumerated an entry point that does not exist.
const table = [{ interval: "*/5 * * * *", jobFunc: vacuum }];
for (const job of table) {
  new Cron(job.interval, { name: "vacuum" }, job.jobFunc);
}

/** Reached only by the registration above. */
function vacuum(): void {
  void db.setting.findFirst();
}

// A named function handed to a scheduler by reference, with the interval and the job's
// own name alongside it. `.bind()` is a detail of what `this` is, not of which function
// runs, so it is looked through.
scheduler.schedule(sweep.bind(null), 3_600_000, "sweep");

/** Reached only by the schedule above. */
async function sweep(): Promise<void> {
  await db.setting.findFirst();
}

// EXPECTED FINDING, AND NOT AN ENTRY POINT -- `setTimeout` is not a schedule.
//
// A one-shot delay is how every debounce, retry and backoff in JavaScript is written.
// Counting it as a scheduled job would bury the four above in a class of callback that is
// neither periodic nor privileged in any way its caller was not.
//
// The SQL injection inside it is reported exactly as it was before this class existed:
// unanchored, never gating, and named after the function it sits in rather than after any
// entry point. That is the difference the class makes, stated as a pair -- the weakness
// was always visible; what was missing was anything to attribute it to.
setTimeout(async () => {
  const job = await db.job.findFirst();
  await sql.query(`DELETE FROM job WHERE command = '${job.command}'`);
}, 250);

// SILENT -- the same method name on a socket.
//
// `socket.on` and `bus.on` are indistinguishable by name, and one production repository in
// this corpus writes a hundred and fifty-three of them. They are not the same entry point:
// a websocket handler answers a REMOTE caller, and labelling one internal would understate
// it as badly as ignoring the bus overstates the rest. The receiver's type decides, and
// where the checker cannot say, nothing is claimed.
socket.on("message", async () => {
  const conf = await db.setting.findFirst();
  await sql.query(`SELECT * FROM setting WHERE name = 'retention'`);
  void conf;
});

// SILENT -- a `schedule` that schedules a meeting.
//
// A bare method name is not an identity. This call is handed two dates and no function,
// so there is no callback to enumerate and no job that will ever run.
planner.schedule("2026-01-01", "2026-01-02");

// SILENT -- a forwarding helper, which is not a job.
//
// This registers whatever its caller hands it: the callback is a PARAMETER of the
// enclosing function, so there is no function here to attribute anything to and the real
// registration is at every call site of `useInterval`. This is the one place a background
// entry point differs from a route, and it is not a lapse from ADR-009 -- a route exists
// at an ADDRESS whether or not its handler resolves, and a job has no address. It IS its
// callback, and a row naming no function contributes no reachability and cannot be
// reasoned about.
export function useInterval(fn: () => void, everyMs: number): void {
  setInterval(fn, everyMs);
}

// SILENT -- an application method that happens to be spelled `schedule`.
//
// `this.schedule(draft)` takes a RECORD and files it for later; nothing about it registers
// a callback, and `draft` is a property access exactly as a real job's `job.jobFunc` is.
// Requiring the argument to RESOLVE to a function is what tells the two apart, and without
// it this shape produced two false entry points in one production repository.
class Drafts {
  schedule(draft: { id: string }): void {
    void draft;
  }

  save(draft: { id: string }): void {
    this.schedule(draft);
  }
}

void Drafts;
