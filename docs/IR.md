# Program IR — v0.6.0

The IR is the contract between language frontends and the core (ADR-001). A frontend
lowers a codebase into this shape and stops. The core consumes only this shape and
produces every finding.

**The IR grows only under demonstrated need.** It began carrying exactly what one
vulnerability class required; every field added since exists because a specific analysis
could not be expressed without it. Nothing is added in anticipation.

## Envelope

```jsonc
{
  "irVersion": "0.16.0",
  "frontend": { "name": "typescript", "version": "0.1.0", "capabilities": { ... } },
  "modules":     [ ... ],
  "functions":   [ ... ],
  "entryPoints": [ ... ]
}
```

### Modules

`isTest` records an ecosystem test convention. `provenance` records why a module is not
ordinary hand-written application source: `vendored`, `example`, or `generated`. Both are
facts supplied by the frontend; reporting and surface analysis decide what those facts are
worth. The files remain in the IR.

### `frontend.capabilities`

What this frontend can actually support (ADR-003). The core refuses to run an analysis
whose requirements are not met and reports **not applicable** — never "clean."

| Field | Meaning |
|---|---|
| `typeChecker` | Real type/symbol resolution was available |
| `interprocedural` | Call sites resolve to callee declarations |
| `crossModule` | Resolution crosses file/module boundaries |
| `controlFlow` | Basic blocks and their successors were built |
| `frameworkModels` | Framework models applied during lowering |

## Functions

A function is the unit of intraprocedural dataflow.

```jsonc
{
  "id": "src/exec-helper.ts#runPing:3",
  "name": "runPing",
  "module": "src/exec-helper.ts",
  "loc": { "file": "...", "line": 3, "column": 1 },
  "params":  [ { "index": 0, "name": "host", "valueId": "..." } ],
  "values":  [ ... ],
  "flows":   [ ... ],
  "calls":   [ ... ],
  "returns": [ "<valueId>" ]
}
```

### Values

A value is a dataflow node. Taint is a property of values.

| `kind` | Meaning |
|---|---|
| `param` | A formal parameter |
| `local` | A local binding |
| `property` | A property access; `base` is the root value, `path` the dotted access |
| `call-result` | The result of a call site |
| `literal` | A literal (never a taint source) |
| `catch-param` | The binding of a catch clause; where internal error detail enters |

`kind` is an **open string**. A frontend may emit kinds the core does not know; unknown
kinds participate in flows and are otherwise inert.

`catch-param` is worth noting as a worked example of that rule: adding it required **no
version change and no core change**. A source rule selects values by kind, so a new
origin is a data change. This is the open-taxonomy decision in ADR-001 paying for itself.

```jsonc
{ "id": "...$v2", "kind": "property", "base": "...$v0", "path": "query.host", "loc": {...} }
{ "id": "...$v5", "kind": "literal", "literal": "8", "loc": {...} }
```

#### `literal` (added in 0.11.0)

The text of a value written into the source, for the kinds that have one. A call's
arguments carried their literals from the beginning, because a defect is often visible in
the call; a COMPARISON needs the same thing for the same reason. Without it the decision
analysis could see that a password was being MEASURED and not what it was being measured
against, and `len(password) < 6` and `len(password) > 72` are the same shape with opposite
meanings.

Numbers are rendered as written and booleans as `true`/`false`. Python renders booleans
before numbers deliberately: `True` IS an `int` there, and writing it as `1` would make a
comparison against a flag look like a comparison against a threshold.

### Flows

A directed intraprocedural dataflow edge. The core propagates taint along these.

```jsonc
{ "from": "...$v2", "to": "...$v3", "kind": "assign", "loc": {...}, "block": "...$b1" }
```

`kind` is descriptive only (`assign`, `property`, `template`, `binary`, `return`) and is
used to render evidence. It does not change propagation in v0.

#### `block` (added in 0.13.0)

The basic block this edge occurs in. Added because a variable that is REDEFINED reaches
the core as one value with two edges into it -- a merge -- and a merge cannot say that
one definition replaced the other. linkwarden's Stripe webhook writes `let event =
req.body`, replaces it ten lines later with the verified event, and logs the verified
one; without a block on each edge the core reported the log as caller-controlled with a
path back to a value that had stopped existing.

**An absent `block` is a refusal, never a default.** A frontend must leave it unset
wherever the block graph does not express when the edge runs: inside a loop body, whose
back edge neither frontend emits, and inside a `switch`, whose arms are lowered
straight-line. The core reads an absent block as "position unknown" and keeps the flow,
which is the only safe direction -- a dropped flow is a missed weakness (ADR-003).

### Calls

A call site. Together, the `calls` of every function form the call graph.

```jsonc
{
  "id": "...$c1",
  "loc": {...},
  "callee": {
    "kind": "local",              // local | external | unresolved
    "functionId": "src/exec-helper.ts#runPing:3",
    "symbol": "child_process.exec", // when kind=external
    "resolution": "resolved"        // resolved | probable | dynamic-unresolved
  },
  "args": [
    { "index": 0, "valueId": "...$v3" },
    { "index": 1, "functionId": "src/app.ts#<anonymous>:25" }  // a function value
  ],
  "method": "then",                 // property name, for a method call
  "receiverValueId": "...$v2",      // the object the method was called on
  "resultValueId": "...$v4",
  "conditionBranch": "falsy",       // direct `if (!call())`: first successor on false
  "receiverType": "Map",            // the receiver's type, when the frontend knows
  "receiverTypeOrigin": "builtin",  // where that type is declared
  "argCount": 2,                    // how many arguments were WRITTEN
  "argLiterals": {                  // arguments written as literals
    "0": "session",                 //   positional, by index
    "-1": "httpOnly=false"          //   an option, by name, numbered from -1 downward
  },
  "enumeratedOptions": [2]          // positions whose option KEYS were read in full
}
```

`resolution` is what drives finding confidence and the pipeline gate (ADR-005). A path
crossing a `dynamic-unresolved` edge cannot produce a high-confidence finding.

### Branch polarity (added in 0.16.0)

`conditionBranch` records branch polarity only when this call is the direct condition:
`truthy` for `if (call())`, `falsy` for `if (!call())`. The first block successor is the
then branch. An absent field makes no claim. This cannot be reconstructed from the CFG:
`if (!allow(value)) return` and `if (allow(value)) return` have identical successor
graphs, but only the first says that every value reaching the following operation passed
the allow-list. Compound conditions are absent unless a frontend can state their
semantics without guessing.

### Receiver type (added in 0.6.0)

`delete` and `update` name a database operation and a `Map` operation equally well.
Describing a record selector by method name alone made every `Set.delete(id)` and every
`heartbeatTimers.delete(id)` into one, and asking who owns an entry in a process-local
map is not a question with an answer — across sixteen production repositories this was
most of what the highest-confidence tier contained.

Which of the two a receiver is, is a question about the LANGUAGE, and only a frontend
can answer it. Whether the answer matters is a question about security, and only the
core answers that. So the frontend states the type and where it is declared, and says
nothing about record selection:

- `receiverType` — the type's name, carried for evidence.
- `receiverTypeOrigin` — `"builtin"` when the type is declared in the language's own
  standard library. The TypeScript frontend reads this from the checker rather than from
  a list of type names, so it stays correct as the language grows.

Absent means the frontend could not tell. **Absent is never "not builtin."** A channel
that needs this answer and does not get one still matches, but the finding cannot reach
the confidence that gates (ADR-005): an analysis must not become more certain because a
frontend went quiet.

### Options and `enumeratedOptions` (added in 0.9.0)

Most misconfiguration is an omission rather than a mistake: nothing wrong was written
down, the right thing was left out. Reporting an omission requires knowing that the thing
really is absent, and not merely that this frontend could not see it — two situations that
look identical unless the IR distinguishes them.

Options are recorded in `argLiterals` under NEGATIVE indices, numbered from -1 downward,
as `name=value`. A JavaScript options object and a Python keyword argument are the same
decision spelled two ways, so both arrive in the same slots and the core needs one
vocabulary rather than two. A key whose value is not a literal is recorded as `name=?`:
the key is known to be set even though the value is decided at runtime.

`argCount` is how many arguments the call site actually has, which is NOT `args.length`:
an argument appears in `args` only when it produced a dataflow value, and a bare global
the frontend could not resolve produces none. A rule that needs to know a call was handed
something cannot ask the value list, because that list is about what could be tracked
rather than about what was written.

Options written one level down inside a named group are recorded too, under the key
`group.name` — `webPreferences.nodeIntegration=true`, `cookie.maxAge=31536000000`,
`ssl.check_hostname=false`. Reading only the top level recorded the GROUP as
present-with-unknown-value while the decision sat one line below it, which is where
options that decide something usually live. Nested keys are numbered below every
top-level one so the two can never collide. The core compares an option key on its last
segment: an option is the same option wherever it sits.

`enumeratedOptions` lists the argument positions whose KEY SET was read in full, with
`-1` standing for keyword arguments taken as a group. A spread (`...defaults`, `**opts`)
hides keys, so an object containing one is not listed and nothing may be concluded from a
key not appearing in it.

Absence of an entry is never evidence of anything. `res.cookie('jwt', t, getCookieOpts())`
sets its attributes in another function; a rule that read that as "sets no attributes"
reported four false positives in a single production file, which is what this field exists
to prevent (ADR-003).

### Why `method`, `receiverValueId`, and `arg.functionId` exist (added in 0.2.0)

These three fields are what make JavaScript's real dataflow expressible, and each was
added because an analysis demonstrably needed it rather than in anticipation:

- **`receiverValueId`** — the taint in `s.trim()` is in the object, not in any argument.
  Without a receiver, every method call on tainted data silently drops the taint.
- **`arg.functionId`** — identifies an argument that *is* a function, so a callback body
  can be connected to the data flowing into the call that receives it.
- **`method`** — the property name, independent of how the receiver was spelled. Matching
  `p.then(...)` on the text of `p` is unreliable; matching on `then` is not.

Together they let the core express one rule — *taint on a receiver reaches the callback's
parameter* — that covers promise continuations and every higher-order collection method,
without the core knowing that JavaScript exists.

### Writes (added in 0.10.0)

```jsonc
{ "loc": {...}, "base": "...$v3", "path": "role", "from": "...$v2", "block": "...$b1" }
{ "loc": {...}, "base": "...$v1", "path": "currentUser", "from": "...$v2", "scope": "process" }
{ "loc": {...}, "base": "...$v4", "key": "...$v0", "from": "...$v6" }
```

An assignment INTO something: `session["user"] = x`, `config.debug = y`. Assignments to a
plain NAME were lowered from the beginning and assignments to a property or a subscript
were not, so putting caller data into a session recorded nothing at all — a weakness whose
entire shape is the write was not merely undetected but unexpressible.

`base` is the value being written into, `path` is the property name or the subscript key
when it was written as a literal, and `from` is the value written.

`scope` (added in 0.11.0) says how far the destination REACHES, for a write whose danger
is not what it writes into but how long that lives. `process` marks state shared by every
request the process handles, so what one caller put there is what the next caller gets.

The frontend decides it, because what makes an assignment reach outside a function is a
rule of the language rather than a property of the destination: Python needs the name
declared `global` and JavaScript needs it bound in an enclosing scope, and the identical
statement without either makes a local and touches nothing. That is why the core cannot
work it out and why the seam is the right place for the answer (ADR-001).

#### `key` (added in 0.14.0)

The value the entry was filed UNDER, for a subscript whose key was computed rather than
written down. `path` already carried a key written as a literal, because a literal key is
a property name spelled differently; the two are never both set.

Added because a write records what was PUT somewhere and the destination's growth is
decided by what it was put under: a container gains one entry per distinct key, and a key
the caller chose has no ceiling the program set. uptime-kuma's
`UptimeCalculator.list[monitorID] = new UptimeCalculator()` arrived with the entry in
`from`, the map in `base`, and the identifier deciding how many maps there can be nowhere
at all.

#### `block` (added in 0.14.0)

The basic block the write occurs in, on exactly the terms a flow carries one. A question
about what a CHECK settled before the write cannot be answered from a line number: two
writes on the same line of two programs sit in different places in the graph, and only one
of them is downstream of a rejection.

**An absent `block` is a refusal, never a default**, and for the same reason it is on a
flow: a write inside a loop body or a switch arm is at a position the block graph does not
express. A judgement that needs the position is not made there rather than being made on a
guess (ADR-003).

Deliberately NOT fed into taint propagation. Whether a value read back out of an object
should carry what was written into it is a field-sensitivity question this project measured
once and found worth nothing, and answering it as a side effect of recording the write
would be deciding it by accident.

### Comparisons (added in 0.4.0)

```jsonc
"comparisons": [ { "left": "...$v4", "right": "...$v7", "op": "!==", "loc": {...} } ]
```

A relational fact: which values were tested against which. Dataflow describes where a
value *went*; it cannot express that a handler checked one thing *against* another, and
"did this handler ever consult who the caller is?" is exactly that question.

Added because the ownership judgement could not be stated without it — a policy that
permits a pairing only when the data was related to another class needs to see the
relating happen.

### Basic blocks (added in 0.5.0)

```jsonc
"entryBlock": "...$b0",
"blocks": [
  { "id": "...$b0", "successors": ["...$b1", "...$b3"], "terminator": "branch", "loc": {...} },
  { "id": "...$b1", "successors": [], "terminator": "return", "loc": {...} }
]
```

Calls, comparisons and flows carry a `block`. A block with no successors is an exit.

Added because a security question could not be answered without it: **does a check
decide anything?** Two handlers can compare the same values with the same operator in
the same position, and one enforces while the other does not — the difference is
whether control can leave early. Positional information cannot express that; a
successor graph can.

Terminators are `branch`, `return`, `throw`, or absent. Frontends that cannot build a
graph set `controlFlow: false`, and policies needing it are reported as unevaluated
rather than satisfied.

## Entry points

Where untrusted input enters. `kind` is an **open string** so a new frontend adds its own
without a core change.

```jsonc
{
  "functionId": "src/app.ts#<anonymous>:9",
  "kind": "http-route",
  "framework": "express",
  "detail": { "method": "GET", "path": "/ping" },
  "middleware": [
    { "functionId": "src/auth.ts#requireAuth:4", "name": "requireAuth",
      "scope": "route", "loc": {...} }
  ]
}
```

Known kinds today: `http-route`, `scheduled-job`, `event-consumer`, `cli-command`,
`process-start`. Reserved by convention: `server-action`, `queue-consumer`.

### `trust` (added in 0.15.0)

Who can cause this entry point to run. **Absent means `remote`**, which is the
conservative reading and the one every entry point had before there was anything but a
route: a frontend that says nothing must not make the core quieter.

| value | meaning |
| --- | --- |
| `remote` | anything that can reach the service. An HTTP route. |
| `operator` | someone who can already run a command on the host or start the process. A management command's arguments, a process's configuration and environment. |
| `internal` | nothing outside the process triggers it. A timer fires it, or an in-process bus delivers to it. |

The surface stopped being all one kind the moment anything but a route was enumerated,
and a cron job is not an anonymous request. The frontend states which it is and the core
decides what it means — the same division `provenance` and `isTest` already draw. A
finding's rank follows the trust of the **source**, not of the entry point holding the
sink: a scheduled job reading a column an HTTP request wrote is carrying a remote
caller's value, and a management command interpolating its own argument into a shell is
not.

```jsonc
{ "functionId": "server/jobs.js#clearOldData:4", "kind": "scheduled-job",
  "trust": "internal", "detail": { "trigger": "Cron", "schedule": "14 03 * * *" } }
{ "functionId": "hc/api/management/commands/smtpd.py#handle:154:5", "kind": "cli-command",
  "framework": "django", "trust": "operator",
  "detail": { "command": "smtpd", "class": "Command", "arguments": "host port" } }
{ "functionId": "jupyterhub/app.py#<module>:0:0", "kind": "process-start",
  "trust": "operator", "detail": { "start": "__main__ guard" } }
```

An entry point that is not a route carries no `method` and no `path`, so `detail` names
it some other way — `command`, `event`, `schedule`, `trigger`, `start` — and a reader
and the core both use whichever is present.

### `middleware` (added in 0.3.0)

The chain applied before a handler runs, which is where cross-cutting security
controls live. Recording it per entry point is what makes a control *enumerable*
rather than merely present somewhere in the file — and enumerability is the
precondition for asserting that one is missing (ADR-009).

`scope` distinguishes a binding attached to this registration (`route`) from one
applied application-wide (`app`). App-scope bindings apply to every route equally, so
they can never distinguish one route from another and are excluded from convention
comparison.

A frontend should emit a middleware reference even when it cannot resolve the target
to a function — an unresolved identifier still has a stable name, and comparing chains
across peers only requires knowing that peers share a binding this one lacks.

## What v0 does not have

Named here so their absence is understood as scope, not oversight: no CFG or path
conditions, no aliasing or points-to, no class/interface hierarchy, no generics, no
property-precise (field-sensitive) taint — a tainted base taints its properties — and no
call-site context, so a function's parameter carries the union of taint from all of its
callers. Each is added when an analysis demonstrably needs it.

Control detection on the surface still establishes only that a control is **present** on
an entry point, not that it runs. Basic blocks exist now, so closing that gap is wiring
rather than new IR.

## Compatibility

`irVersion` is semver. The core rejects an IR whose major version it does not implement.
Frontends and core version independently; the wire format is the only coupling.
