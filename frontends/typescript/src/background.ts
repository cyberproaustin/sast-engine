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
 * Packages whose types mean "a connection somebody outside this process opened".
 *
 * Matched on where the type is DECLARED rather than on what it is called, because the
 * name is worth nothing: `Socket` is socket.io's connection, node's raw TCP stream and,
 * in one corpus fixture, a class a test file declares. One of those answers a remote
 * caller and the others do not, and only the declaration tells them apart.
 */
const REMOTE_DISPATCHER_PACKAGES = [
  /[/\\]node_modules[/\\]socket\.io[/\\]/,
  /[/\\]node_modules[/\\]socket\.io-client[/\\]/,
  /[/\\]node_modules[/\\]ws[/\\]/,
];

/**
 * The one DOM event that is a channel rather than a gesture.
 *
 * `addEventListener` is how every button in every page is wired up, and enumerating those
 * would bury the surface in clicks -- 172 of them in one repository here. `message` is the
 * exception and it is not a matter of degree: a `message` event carries data another
 * document, another origin or another thread sent, which is a boundary, and a `click`
 * carries the fact that somebody who is already looking at the page pressed something.
 */
const CROSS_REALM_EVENT = "message";

/**
 * The events that ARE a channel, for a listener registered on a global.
 *
 * `message` is what another document, another origin or another thread sent. `fetch` is a
 * service worker being handed every request the page it controls makes, which is an
 * interception surface and the reason a service worker needs a review at all. Three
 * `fetch` listeners exist across the ten production repositories measured here and every
 * one of them is a service worker; there is no second meaning of the word to confuse it
 * with, because no element fires it.
 */
const CROSS_REALM_EVENTS = new Set([CROSS_REALM_EVENT, "fetch"]);

/**
 * Where a browser extension's own message channels live. `chrome.runtime.onMessage`,
 * `browser.runtime.onMessageExternal`, `chrome.webRequest.onBeforeRequest`: a property
 * chain rooted at the extension global, ending in an event object whose `addListener`
 * takes the callback and no key at all -- the event object IS the key.
 */
const EXTENSION_ROOTS = new Set(["chrome", "browser"]);

/**
 * The key a server announces an accepted client under. One word, and every server library
 * in this ecosystem uses it for exactly this: socket.io, `ws`, `net`, `tls`, `http`.
 */
const ACCEPTED_CONNECTION = "connection";

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

/**
 * The parameters that hold a connection somebody outside the process opened.
 *
 * This is the answer to a problem the type checker cannot solve on a repository as it is
 * PUBLISHED: none of the ten production trees this engine is measured against ships its
 * `node_modules`, so no dependency's types resolve and `socket.io`'s `Socket` is a name
 * with nothing behind it. A rule that waited for the checker to confirm the package would
 * enumerate nothing on any real checkout.
 *
 * What needs no dependency at all is the SHAPE. A server that accepts clients announces
 * each one under the key `connection` -- socket.io, `ws`, node's own `net` and `tls`
 * servers all do, and none of them means anything else by it -- so the callback's first
 * parameter IS the connection, and every `.on(key, handler)` on that parameter is a route
 * a remote caller reaches. The identity is self-evidencing: it comes from the program's
 * own text rather than from a list of package names that goes stale.
 *
 * Propagated through calls, because that is how applications are written: uptime-kuma
 * accepts the connection in `server.js` and hands it to ten handler modules, which is 48
 * of its 87 registrations. One socket, ten files, and the parameter is the only thing
 * tying them together.
 */
export function connectionParameters(
  sources: readonly ts.SourceFile[],
  checker: ts.TypeChecker,
): Set<ts.Symbol> {
  const found = new Set<ts.Symbol>();

  /** The function a callback argument denotes, however it was written. */
  const declarationOf = (node: ts.Expression): ts.SignatureDeclaration | undefined => {
    const target = unbind(node);
    if (ts.isArrowFunction(target) || ts.isFunctionExpression(target)) return target;
    let symbol: ts.Symbol | undefined;
    try {
      symbol = checker.getSymbolAtLocation(target);
    } catch {
      return undefined;
    }
    for (const d of symbol?.getDeclarations() ?? []) {
      if (ts.isFunctionDeclaration(d) || ts.isMethodDeclaration(d)) return d;
      if ((ts.isVariableDeclaration(d) || ts.isPropertyAssignment(d)) && d.initializer &&
          (ts.isArrowFunction(d.initializer) || ts.isFunctionExpression(d.initializer))) {
        return d.initializer;
      }
    }
    // The name is a re-export, a destructured `require`, or a property of a module
    // object, and its declaration is the binding rather than the function. What the value
    // CAN BE CALLED AS survives all three: uptime-kuma's ten socket handlers are assigned
    // to `module.exports` in one file and destructured out of a `require` in another, and
    // they are 48 of its 87 registrations.
    try {
      const decl = checker.getTypeAtLocation(target).getCallSignatures()[0]?.declaration;
      if (decl && ts.isFunctionLike(decl)) return decl as ts.SignatureDeclaration;
    } catch {
      return undefined;
    }
    return undefined;
  };

  const mark = (fn: ts.SignatureDeclaration | undefined, index: number): boolean => {
    const param = fn?.parameters[index];
    if (!param) return false;
    let symbol: ts.Symbol | undefined;
    try {
      symbol = checker.getSymbolAtLocation(param.name);
    } catch {
      return false;
    }
    if (!symbol || found.has(symbol)) return false;
    found.add(symbol);
    return true;
  };

  for (const sf of sources) {
    const seed = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
          SUBSCRIBE_METHODS.has(node.expression.name.text) &&
          node.arguments.length >= 2 && ts.isStringLiteralLike(node.arguments[0]) &&
          node.arguments[0].text === ACCEPTED_CONNECTION) {
        mark(declarationOf(node.arguments[1]), 0);
      }
      ts.forEachChild(node, seed);
    };
    seed(sf);
  }

  // A fixpoint, and a bounded one. Each round can only add parameters, so it terminates
  // on its own; the cap is there because the walk is over every call in the program and a
  // chain longer than this is not a shape any of these applications has.
  for (let round = 0; round < 4; round++) {
    let grew = false;
    for (const sf of sources) {
      const walk = (node: ts.Node): void => {
        if (ts.isCallExpression(node)) {
          for (let i = 0; i < node.arguments.length; i++) {
            const arg = node.arguments[i];
            if (!ts.isIdentifier(arg)) continue;
            let symbol: ts.Symbol | undefined;
            try {
              symbol = checker.getSymbolAtLocation(arg);
            } catch {
              continue;
            }
            if (!symbol || !found.has(symbol)) continue;
            if (mark(declarationOf(node.expression), i)) grew = true;
          }
        }
        ts.forEachChild(node, walk);
      };
      walk(sf);
    }
    if (!grew) break;
  }
  return found;
}

/**
 * Classes that ROUTE what arrives from another realm, found by what they do rather than
 * by what they are called.
 *
 * A worker RPC layer is written the same way everywhere: the constructor subscribes to
 * `message` on a port it was handed, and the class offers an `on(name, handler)` that
 * files each handler under a name. pdf.js's `MessageHandler` is exactly that, and its 48
 * registrations are the whole of what the worker answers -- a surface that was empty
 * because the class is the application's own and no type name could have been listed for
 * it in advance.
 *
 * BOTH halves are required. A class that only subscribes to `message` is a listener and
 * has no keys; a class that only offers `on` is an event bus, which is already covered by
 * the EventEmitter test and carries a different trust.
 *
 * Collected across the whole program before anything is lowered, because the class is
 * declared in one file and used in another.
 */
export function messagePortDispatchers(sf: ts.SourceFile): string[] {
  const out: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isClassDeclaration(node) && node.name) {
      let subscribes = false;
      let routes = false;
      for (const member of node.members) {
        if ((ts.isMethodDeclaration(member) || ts.isPropertyDeclaration(member)) &&
            member.name && ts.isIdentifier(member.name) && SUBSCRIBE_METHODS.has(member.name.text)) {
          routes = true;
        }
      }
      const body = (n: ts.Node): void => {
        if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) &&
            n.expression.name.text === "addEventListener" &&
            n.arguments.length >= 2 && ts.isStringLiteralLike(n.arguments[0]) &&
            n.arguments[0].text === CROSS_REALM_EVENT) {
          subscribes = true;
        }
        if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
            ts.isPropertyAccessExpression(n.left) && n.left.name.text === "onmessage") {
          subscribes = true;
        }
        ts.forEachChild(n, body);
      };
      ts.forEachChild(node, body);
      if (subscribes && routes) out.push(node.name.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
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
 * Which argument is the callback — and it must RESOLVE to a function.
 *
 * This is the one place where a background entry point differs from a route, and the
 * difference is not a lapse from ADR-009. A route exists at an ADDRESS: `app.post("/x",
 * controller.register)` is reachable by anyone who can spell `/x`, whether or not the
 * frontend can find `register`, so dropping it would hide part of the surface. A
 * background job has no address. It IS its callback, and a registration whose callback
 * cannot be named contributes no reachability, can anchor nothing, and adds a row to the
 * surface that nobody can reason about.
 *
 * Measured on ten repositories: allowing an unresolved argument through produced five
 * entry points and every one of them was wrong. Two were `this.schedule(draft)` — an
 * application's own method that takes a RECORD, matched because it happens to be spelled
 * `schedule` — and three were forwarding helpers (`useInterval(fn, ms)` calling
 * `setInterval(fn, ...)`, an event store re-exposing its bus as `on(name, listener)`)
 * where the callback is a parameter of the enclosing function and the real registration
 * is at each call site. It bought nothing and cost five false rows.
 *
 * The argument ORDER is not fixed across schedulers, so the first argument that resolves
 * is taken. `new Cron(job.interval, {...}, job.jobFunc)` is the shape that makes this
 * work: `job.interval` and `job.jobFunc` are the same syntax and only one of them is a
 * function the program defines.
 */
function selectCallback(
  args: readonly ts.Expression[],
  resolveFunction: ResolveFunction,
): { index: number; fn: FuncRef } | undefined {
  for (let i = 0; i < args.length; i++) {
    const fn = resolveFunction(unbind(args[i]));
    if (fn) return { index: i, fn };
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

/** The text an event name was written as, when it is not a string literal. */
function textOf(node: ts.Node): string {
  const t = node.getText(node.getSourceFile()).replace(/\s+/g, " ");
  return t.length > 60 ? t.slice(0, 57) + "..." : t;
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
  dispatchers: ReadonlySet<string> = new Set(),
  connections: ReadonlySet<ts.Symbol> = new Set(),
): EntryPoint[] {
  const out: EntryPoint[] = [];

  const symbolOf = (node: ts.Expression): ts.Symbol | undefined => {
    let type: ts.Type;
    try {
      type = checker.getTypeAtLocation(node);
    } catch {
      return undefined;
    }
    return type.getSymbol() ?? type.aliasSymbol;
  };

  const receiverTypeName = (node: ts.Expression): string => {
    const symbol = symbolOf(node);
    return symbol ? symbol.getName() : "";
  };

  /** Where the receiver's type is DECLARED. A name is not an identity; a file is. */
  const declaredIn = (node: ts.Expression): string[] => {
    const symbol = symbolOf(node);
    return (symbol?.getDeclarations() ?? []).map((d) => d.getSourceFile().fileName);
  };

  /**
   * What KIND of dispatcher a receiver is, or nothing.
   *
   * Three answers and they carry three different trusts, which is the whole reason this
   * is one function rather than a list of method names. A bus nobody outside the process
   * can post to is internal. A socket.io connection is a caller on the other end of a
   * network, which is remote. A worker RPC router carries what another realm of this same
   * program sent, which is internal again -- and saying so is the difference between "a
   * stranger can do this to you" and "your own worker can".
   */
  const dispatcherOf = (recv: ts.Expression): { bus: string; trust: "remote" | "internal" } | undefined => {
    if (ts.isIdentifier(recv)) {
      let symbol: ts.Symbol | undefined;
      try {
        symbol = checker.getSymbolAtLocation(recv);
      } catch {
        symbol = undefined;
      }
      if (symbol && connections.has(symbol)) return { bus: "connection", trust: "remote" };
    }
    const name = receiverTypeName(recv);
    if (name && dispatchers.has(name)) return { bus: name, trust: "internal" };
    const files = declaredIn(recv);
    for (const file of files) {
      for (const pkg of REMOTE_DISPATCHER_PACKAGES) {
        if (pkg.test(file)) return { bus: name || "socket", trust: "remote" };
      }
    }
    if (name && EVENT_EMITTER_TYPE.test(name)) return { bus: name, trust: "internal" };
    return undefined;
  };

  /**
   * `chrome.runtime.onMessage` and its siblings, by the spelling that IS their identity.
   *
   * An extension event object takes the callback and no key, because the object is the
   * key. Rooted at the extension global and nowhere else: `emitter.onMessage.addListener`
   * would be an ordinary object with an ordinary property.
   */
  const extensionChannel = (recv: ts.Expression): string | undefined => {
    const parts: string[] = [];
    let cur: ts.Expression = recv;
    while (ts.isPropertyAccessExpression(cur)) {
      parts.unshift(cur.name.text);
      cur = cur.expression;
    }
    if (!ts.isIdentifier(cur) || !EXTENSION_ROOTS.has(cur.text) || parts.length === 0) return undefined;
    if (!/^on[A-Z]/.test(parts[parts.length - 1])) return undefined;
    return [cur.text, ...parts].join(".");
  };

  const push = (
    kind: string,
    node: ts.Node,
    detail: Record<string, string>,
    fn: FuncRef,
    trust: "remote" | "internal" = "internal",
  ): void => {
    out.push({
      functionId: fn.id,
      kind,
      trust,
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
    let chosen: { index: number; fn: FuncRef } | undefined;
    if (fixed !== undefined) {
      if (args.length <= fixed) return;
      const fn = resolveFunction(unbind(args[fixed]));
      if (fn) chosen = { index: fixed, fn };
    } else {
      chosen = selectCallback(args, resolveFunction);
    }
    if (!chosen) return;
    const detail: Record<string, string> = { trigger, module: locOf(node).file };
    const every = scheduleText(args, chosen.index);
    if (every) detail.schedule = every;
    push("scheduled-job", node, detail, chosen.fn);
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
      } else if (ts.isIdentifier(callee) && callee.text === "addEventListener" &&
                 node.arguments.length >= 2 && ts.isStringLiteralLike(node.arguments[0]) &&
                 CROSS_REALM_EVENTS.has(node.arguments[0].text)) {
        // The same channel written without naming the global, which is how a worker's own
        // top level subscribes to the thread that started it.
        const event = node.arguments[0].text;
        const fn = resolveFunction(unbind(node.arguments[1]));
        if (fn) {
          push(
            "event-consumer",
            node,
            { trigger: "addEventListener", event, bus: "global", module: locOf(node).file },
            fn,
            "remote",
          );
        }
      } else if (ts.isPropertyAccessExpression(callee)) {
        const method = callee.name.text;
        // `window.setInterval(fn, ms)` is the same registration written through the
        // global object, which is how browser-adjacent code spells it.
        if (INTERVAL_FUNCTIONS.has(method)) {
          schedule(node, method, node.arguments, 0);
        } else if (SCHEDULE_METHODS.has(method)) {
          schedule(node, method, node.arguments);
        } else if (SUBSCRIBE_METHODS.has(method) && node.arguments.length >= 2) {
          const found = dispatcherOf(callee.expression);
          if (found) {
            const fn = resolveFunction(unbind(node.arguments[1]));
            if (fn) {
              const name = ts.isStringLiteralLike(node.arguments[0])
                ? node.arguments[0].getText(sf).slice(1, -1)
                : textOf(node.arguments[0]);
              push(
                "event-consumer",
                node,
                { trigger: method, event: name, bus: found.bus, module: locOf(node).file },
                fn,
                found.trust,
              );
            }
          }
        } else if (method === "addListener" && node.arguments.length === 1) {
          // An extension event object: the object IS the key, so the callback is the
          // only argument. A content script, a page the extension was granted, or another
          // extension puts the message on the other end.
          const channel = extensionChannel(callee.expression);
          const fn = channel ? resolveFunction(unbind(node.arguments[0])) : undefined;
          if (channel && fn) {
            push(
              "event-consumer",
              node,
              { trigger: "addListener", event: channel, bus: "extension", module: locOf(node).file },
              fn,
              "remote",
            );
          }
        } else if (method === "addEventListener" && node.arguments.length >= 2 &&
                   ts.isStringLiteralLike(node.arguments[0]) &&
                   CROSS_REALM_EVENTS.has(node.arguments[0].text)) {
          // `window.addEventListener("message", ...)`, `self.addEventListener("message",
          // ...)` on a worker, and a service worker's `fetch`. Those two names and no
          // others: they are boundaries, and every other DOM event is a gesture from
          // somebody already looking at the page.
          const event = node.arguments[0].text;
          const fn = resolveFunction(unbind(node.arguments[1]));
          if (fn) {
            push(
              "event-consumer",
              node,
              {
                trigger: "addEventListener",
                event,
                bus: receiverTypeName(callee.expression) || textOf(callee.expression),
                module: locOf(node).file,
              },
              fn,
              "remote",
            );
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}
