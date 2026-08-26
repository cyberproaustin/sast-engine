// Background entry points: code the process runs on its own, with no caller.
//
// An HTTP route is not the only way into an application. A scheduled job runs
// unattended over whatever the store already holds, and an event-bus consumer runs
// over whatever an earlier request put on the bus — both with the application's full
// privileges, and neither reachable by anyone outside the process. Until they were
// enumerated, none of that code was reachable from anything, so nothing in it could be
// judged at all (ADR-009).
//
// Isolated in its own module for the same reason the framework models are (ADR-004):
// nothing in lower.ts knows what a cron library is.

import ts from "typescript";
import type { EntryPoint } from "./ir.ts";
import type { FuncRef, ResolveFunction } from "./express.ts";

/**
 * Constructors that ARE a schedule. `new Cron("*\/5 * * * *", fn)` (croner) and
 * `new CronJob(expr, fn)` (cron) both register a recurring job in their constructor,
 * which is a registration written as a `new` rather than as a call.
 */
const SCHEDULE_CONSTRUCTORS = new Set(["Cron", "CronJob", "ScheduledTask"]);

/**
 * Methods that register a recurring callback.
 *
 * A bare method name is not an identity, so each of these is only taken when the call
 * is ALSO handed something callable — `x.schedule(fn, 60_000, 'name')` and
 * `cron.schedule('* * * * *', fn)` are the two argument orders in the wild, and a
 * `schedule` that receives no function at all is something else entirely.
 */
const SCHEDULE_METHODS = new Set(["schedule", "scheduleJob", "scheduleIntervalJob"]);

/**
 * Methods that subscribe to an event bus.
 *
 * These are only taken when the CHECKER says the receiver is an EventEmitter. The name
 * on its own means nothing: `socket.on`, `stream.on`, `process.on`, `res.on` and
 * `child.on` are the same three letters, one repository in this corpus writes 153 of
 * them, and a websocket handler is a REMOTE entry point rather than an internal one --
 * so guessing here would mislabel the trust as well as inflate the count.
 */
const SUBSCRIBE_METHODS = new Set(["on", "once", "addListener"]);

/** The receiver type names that mean "an in-process event bus". */
const EVENT_EMITTER_TYPE = /EventEmitter$/;

/**
 * `setTimeout` is deliberately absent from the scheduler set.
 *
 * A one-shot delay is how every debounce, retry and animation step in JavaScript is
 * written; a scheduled job is code that runs unattended and repeatedly over data the
 * process persisted. Counting the first as the second would drown the real jobs in a
 * class of callback that is neither periodic nor privileged in any way its caller was
 * not.
 */
const INTERVAL_FUNCTIONS = new Set(["setInterval"]);

/** The text a value was written as, for evidence when nothing resolved. */
function textOf(node: ts.Node): string {
  const t = node.getText(node.getSourceFile()).replace(/\s+/g, " ");
  return t.length > 60 ? t.slice(0, 57) + "..." : t;
}

/** `f.bind(this)` — a detail of what `this` is, not of which function runs. */
function unbind(node: ts.Expression): ts.Expression {
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === "bind"
  ) {
    return node.expression.expression;
  }
  return node;
}

/**
 * Whether this argument was WRITTEN as a reference to something callable.
 *
 * Not a claim that it is one: `job.jobFunc` and `job.interval` are the same syntax and
 * only the position tells them apart. Used only as the fallback below, where the last
 * such argument is taken and everything plainly not callable — a string, a number, an
 * options object, a call that computes a duration — is passed over.
 */
function referenceLike(node: ts.Expression): boolean {
  const bare = unbind(node);
  return ts.isIdentifier(bare) || ts.isPropertyAccessExpression(bare);
}

/**
 * Which argument is the callback, and the function it names when that is knowable.
 *
 * Two passes, because the argument ORDER is not fixed across schedulers. First an
 * argument the program defines a function for — an inline arrow, or a name that
 * resolves. Failing that, the LAST argument written as a reference: `new Cron(
 * job.interval, {...}, job.jobFunc)` puts a property access in the first slot and the
 * callback in the last, and taking the first reference would have scheduled the cron
 * expression.
 */
function selectCallback(
  args: readonly ts.Expression[],
  resolveFunction: ResolveFunction,
): { index: number; fn?: FuncRef } | undefined {
  for (let i = 0; i < args.length; i++) {
    const fn = resolveFunction(unbind(args[i]));
    if (fn) return { index: i, fn };
  }
  for (let i = args.length - 1; i >= 0; i--) {
    if (referenceLike(args[i])) return { index: i };
  }
  return undefined;
}

/** The literals a registration was written with: a cron expression, an interval, a name. */
function scheduleText(args: readonly ts.Expression[], skip: number): string {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (i === skip) continue;
    if (ts.isStringLiteralLike(args[i])) out.push(args[i].getText(args[i].getSourceFile()).slice(1, -1));
    else if (ts.isNumericLiteral(args[i])) out.push((args[i] as ts.NumericLiteral).text);
  }
  return out.join(" ");
}

/**
 * Finds scheduled jobs and event-bus consumers, and returns each callback as an entry
 * point that no remote caller can reach.
 */
export function detectBackgroundEntries(
  sf: ts.SourceFile,
  checker: ts.TypeChecker,
  resolveFunction: ResolveFunction,
  locOf: (node: ts.Node) => { file: string; line: number; column: number },
): EntryPoint[] {
  const out: EntryPoint[] = [];

  const receiverTypeName = (node: ts.Expression): string => {
    let type: ts.Type;
    try {
      type = checker.getTypeAtLocation(node);
    } catch {
      return "";
    }
    const symbol = type.getSymbol() ?? type.aliasSymbol;
    return symbol ? symbol.getName() : "";
  };

  const push = (
    kind: string,
    node: ts.Node,
    detail: Record<string, string>,
    chosen: { index: number; fn?: FuncRef },
    args: readonly ts.Expression[],
  ): void => {
    // A registration whose callback did not resolve STILL REGISTERS. Dropping it makes
    // the enumeration silently incomplete, which is the one thing a surface may never
    // be (ADR-009); naming what it was written as turns a blank into a stated gap.
    if (!chosen.fn) detail.handler = textOf(args[chosen.index]);
    out.push({
      functionId: chosen.fn ? chosen.fn.id : "",
      kind,
      // Nothing outside the process can make either of these run.
      trust: "internal",
      detail,
      loc: locOf(node),
    });
  };

  const schedule = (
    node: ts.CallExpression | ts.NewExpression,
    trigger: string,
    args: readonly ts.Expression[],
    fixed?: number,
  ): void => {
    let chosen: { index: number; fn?: FuncRef } | undefined;
    if (fixed !== undefined) {
      if (args.length <= fixed) return;
      const fn = resolveFunction(unbind(args[fixed]));
      if (!fn && !referenceLike(args[fixed]) && !ts.isFunctionExpression(args[fixed])) return;
      chosen = { index: fixed, fn };
    } else {
      chosen = selectCallback(args, resolveFunction);
    }
    if (!chosen) return;
    const detail: Record<string, string> = { trigger, module: locOf(node).file };
    const every = scheduleText(args, chosen.index);
    if (every) detail.schedule = every;
    push("scheduled-job", node, detail, chosen, args);
  };

  const visit = (node: ts.Node): void => {
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
      if (SCHEDULE_CONSTRUCTORS.has(node.expression.text)) {
        schedule(node, node.expression.text, node.arguments ?? []);
      }
    } else if (ts.isCallExpression(node)) {
      const callee = node.expression;
      if (ts.isIdentifier(callee) && INTERVAL_FUNCTIONS.has(callee.text)) {
        schedule(node, callee.text, node.arguments, 0);
      } else if (ts.isPropertyAccessExpression(callee)) {
        const method = callee.name.text;
        // `window.setInterval(fn, ms)` is the same registration written through the
        // global object, which is how browser-adjacent code spells it.
        if (INTERVAL_FUNCTIONS.has(method)) {
          schedule(node, method, node.arguments, 0);
        } else if (SCHEDULE_METHODS.has(method)) {
          schedule(node, method, node.arguments);
        } else if (SUBSCRIBE_METHODS.has(method) && node.arguments.length >= 2) {
          const type = receiverTypeName(callee.expression);
          if (EVENT_EMITTER_TYPE.test(type)) {
            const fn = resolveFunction(unbind(node.arguments[1]));
            if (fn || referenceLike(node.arguments[1])) {
              const name = ts.isStringLiteralLike(node.arguments[0])
                ? node.arguments[0].getText(sf).slice(1, -1)
                : textOf(node.arguments[0]);
              push(
                "event-consumer",
                node,
                { trigger: method, event: name, bus: type, module: locOf(node).file },
                { index: 1, fn },
                node.arguments,
              );
            }
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}
