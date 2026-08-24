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
  "irVersion": "0.6.0",
  "frontend": { "name": "typescript", "version": "0.1.0", "capabilities": { ... } },
  "modules":     [ ... ],
  "functions":   [ ... ],
  "entryPoints": [ ... ]
}
```

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
```

### Flows

A directed intraprocedural dataflow edge. The core propagates taint along these.

```jsonc
{ "from": "...$v2", "to": "...$v3", "kind": "assign", "loc": {...} }
```

`kind` is descriptive only (`assign`, `property`, `template`, `binary`, `return`) and is
used to render evidence. It does not change propagation in v0.

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
  "receiverType": "Map",            // the receiver's type, when the frontend knows
  "receiverTypeOrigin": "builtin"   // where that type is declared
}
```

`resolution` is what drives finding confidence and the pipeline gate (ADR-005). A path
crossing a `dynamic-unresolved` edge cannot produce a high-confidence finding.

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

Calls and comparisons carry a `block`. A block with no successors is an exit.

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

Known kinds today: `http-route`. Reserved by convention: `server-action`,
`queue-consumer`, `cli`, `event-handler`.

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
