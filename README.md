# SAST Engine

> **Status: early implementation.** Two language frontends (TypeScript/Node, Python) share one analysis core. Three analyses run end to end — two dataflow flows (untrusted input reaching a dangerous operation, and sensitive data reaching an exposed channel) plus access-control convention deviation over an enumerated attack surface. It is not usable on real codebases. See [What Exists Today](#what-exists-today) for the precise scope.

## Overview

This project is an exploration of static application security testing — analyzing source code for security defects without executing it — with a specific interest in the gap between what static analysis is capable of proving and what it is actually used for in practice.

The project focuses on analysis that runs inside a delivery pipeline, evaluates code against recognized application security criteria, and produces findings that an engineer can act on without first having to determine whether the finding is real.

## The Problem

Static analysis is one of the oldest ideas in application security and remains one of the least trusted in practice. The reasons are consistent across organizations.

**Precision.** Pattern-oriented analysis matches syntax, but whether a construct is dangerous usually depends on semantics the analyzer does not model — which framework is in use, whether an ORM parameterizes queries, whether a template layer escapes output, whether a middleware already validated the input, whether a sanitizer on the path is adequate for the sink it feeds. Analyzers that lack this context resolve ambiguity by reporting, and the result is a volume of false positives that costs more attention than the true positives return.

**The trust spiral that follows.** Once a tool has been wrong often enough, engineers stop reading its output. Findings are suppressed in bulk, the gate is moved from blocking to advisory, and the scan continues to run while influencing nothing. The tool has not been removed; it has been rendered inert, which is worse, because its presence still counts as coverage.

**Coverage skew.** Static analysis is strongest on the vulnerability classes that have local, syntactic signatures — injection, unsafe deserialization, weak cryptographic usage, hardcoded credentials. It is weakest on the classes that dominate real-world incidents: broken access control, insecure design, and authentication flaws. These are properties of a system's intent, and intent is not present in the code as a pattern to match. The categories most likely to cause a breach are the ones conventional SAST is least equipped to examine.

**Pipeline friction.** Analysis that takes too long, that reports the entire historical backlog on every run, or that loses a finding's identity when a function is renamed will not survive contact with a development team's tolerance for interruption.

## The Central Idea

The project is interested in static analysis that treats **the credibility of a finding as part of the finding**.

Three commitments follow from that.

The first is **evidence over assertion**. A useful result should carry a reviewable justification — the path from an untrusted entry point to a dangerous operation, the sanitizers considered and why they were judged insufficient, and the conditions under which the path is taken. A finding that cannot explain itself imposes the analyst's work on the reader.

The second is **framework and application semantics**. Meaningful precision requires knowing how the application is actually constructed: where its entry points are, which routes exist, what authorization applies to them, which operations reach a data store, and what the framework already guarantees. Analysis that models an application only as text will keep making the same category of mistake.

The third is **change-scoped operation**. In a pipeline, the relevant question is almost always what a specific change introduced, not what the repository has accumulated. Historical debt is a separate conversation deserving separate handling, and conflating the two is the most common reason a gate becomes unenforceable.

## Assessment Criteria

The project's initial interest is in evaluating code against the OWASP application security corpus — the Top 10 as a reporting and communication framework, with the more granular underlying taxonomies as the basis for what is actually asserted about a codebase.

An explicit goal is honesty about coverage. Static analysis can address some OWASP categories well, some partially, and some not at all. The project is interested in stating which is which, rather than mapping every rule to a category label and implying uniform coverage across all of them.

## Areas of Exploration

- **Dataflow and taint analysis** — source-to-sink reasoning, and the difference between analysis confined to a single function and analysis that follows values across functions and files
- **Framework semantics** — modeling the guarantees and hazards specific to a framework rather than treating all code as generic
- **Entry point and route modeling** — deriving an application's exposed surface and the controls attached to it directly from code
- **Sanitizer and control recognition** — determining whether a mitigation on a path is adequate for the specific sink it protects
- **Access control analysis** — reasoning about authorization as a property of an application's structure, the category conventional static analysis most consistently misses
- **Finding identity** — stable fingerprints that survive refactoring, so triage decisions persist and moved code does not resurface as new
- **Baseline and differential analysis** — separating what a change introduced from what the codebase already contained
- **Interoperability** — standard finding formats so results are consumable by other systems rather than trapped in a single tool
- **Gate policy** — expressing what should block a pipeline and what should be recorded, as a deliberate decision rather than a severity threshold
- **Remediation guidance** — fix suggestions with a basis for believing they are correct

## What Exists Today

Every layer of the intended architecture, present in its smallest honest form: a
frontend that lowers real semantics, an IR that is the only seam, an enumerated surface,
and analyses that assert over it.

```
frontends/typescript/   TS/JS via the TypeScript compiler's checker   (Express model)
                        + its views: EJS, Handlebars, Mustache, Pug, Nunjucks, Swig
frontends/python/       Python via the stdlib ast module              (Flask model)
                        + its views: Jinja2
        │
        │  Program IR  (docs/IR.md — the only thing that crosses this boundary)
        ▼
core/                   Go engine: enumerates the attack surface, then asserts over it
                        — dataflow, convention analysis, evidence, SARIF
```

**Two languages, one set of judgements.** The Flask corpus is found by policies written
against Express corpora. Adding Python required a frontend, one classification rule (a
request object that is a module global rather than a handler parameter), and two channel
descriptions — **no policy changed, and the propagation engine was untouched**. Tests
assert that findings in both languages cite the same policy.

The Python frontend has no type inference and declares that. The difference shows up as
*lower confidence*, not as a missing finding: the same cross-module injection is reported,
tiered `low` because `.get()` cannot be resolved, and therefore does not gate. Silence
would have been indistinguishable from safety.

**The primary output is the enumerated surface, not a finding list.** Every entry point is
listed with the controls attached to it, whether or not anything was flagged, because a
conclusion is only worth as much as the enumeration it rests on — an operator who cannot
recognize their own application in the surface should not trust the findings either.
Findings are assertions over that model (ADR-009), which is what lets the engine report a
control that is *missing* — a defect no pattern can match, because nothing is there.

**Taint analysis.** Detects command injection reaching `child_process.exec` from Express
request data and reports the source-to-sink path hop by hop. Taint is followed across
function and module boundaries, through `await` and promise continuations, through methods
called on tainted values (`s.trim()`), and into higher-order callbacks
(`hosts.forEach(h => ...)`) — the boundaries a first-order engine loses, and most of what
Node code is made of. Route handlers are recognized whether they are inline arrows or named
functions.

Sanitizers are evaluated against the sink's context, so a URL encoder is recorded as
considered-and-insufficient for a shell sink rather than silently clearing taint. Findings
are tiered by how well the call graph resolved, not by severity. Output is human-readable
text or SARIF with the evidence path as a `codeFlow`.

**It can be adopted on a codebase that already has findings.** Each finding carries a
fingerprint built from what it *is* — the judgement, the entry point, the file and
function holding the operation, the symbol reached — and never from where it currently
sits, so inserting an import above a defect does not turn it into a new defect. A
baseline records those fingerprints; a recorded finding is still reported, still counted,
still evidenced, and marked as recorded. The only thing it stops doing is failing the
build. That is deliberately not the same as a suppression list, and the distinction is
load-bearing (ADR-014): a declaration says *this is not a defect and here is why*, which
keeps paying on code nobody has written yet, while a baseline says only *this was already
here on Tuesday*. Only the first belongs in the policy file, and only the first should
ever make a finding disappear.

**How a defect is defined.** Not as a pattern, and not as a source/sink pair, but as a
three-part judgement (ADR-012):

| | |
|---|---|
| **Classification** | what a value *is*, determined by where it came from — `untrusted-input`, `internal-error` |
| **Channel** | what a destination *is* — its visibility (`public`, `operator`, `thirdparty`, `internal`) and the syntax it interprets (`shell`, `html`, `http-response`) |
| **Policy** | which pairings are forbidden — or permitted only when the data was *related to* another class |

Expectations about controls carry an **origin**, and the origin decides what they are
worth: *inferred* from the population (ADR-010) informs but never gates; *declared* by the
team (ADR-011) gates. A team that wrote down what it expects has earned an enforceable
claim; a guess about what it probably meant has not.

Nothing in the model names a vulnerability. A defect is what happens when a policy is
violated, and the finding states the reasoning: *internal failure detail reached a channel
visible outside this system*.

This is what makes the rules find things nobody enumerated. A corpus in the repo
demonstrates it: internal error detail forwarded to a third-party webhook is caught with
**no new policy and no engine change** — the model gained only a description of what an
outbound HTTP call is, and the existing policy about internal detail leaving the system
already covered it. The same judgement covers the HTTP response body. A test asserts both
findings cite the same policy.

**Two policy modalities.** *Denies* covers "this must never happen." *Requires a relation*
covers "this is only safe when it was checked" — which is how ownership works. And "checked"
means the check actually decides something:

```js
if (order.userId !== req.user.id) { res.status(403); return; }  // enforcement
if (order.userId !== req.user.id) { console.warn("mismatch"); } // decoration
```

Same values, same operator, same position. The engine separates them by control flow: a
guard is a branch from which control can leave the handler, so its paths never reconverge.
A branch whose paths rejoin decided nothing. The corpus contains both, and only the second
is reported.

```
[MEDIUM] Missing ownership check (CWE-639)
  the caller chooses which record is operated on, and the handler never consults who the caller is
  entry: DELETE /api/orders/:id [express]
  sink:  prisma.order.delete argument 0 at app.ts:17:9
         removes a single record by the identifier it is given
```

That policy mentions neither reading nor deleting, and names no ORM. It says: *a
caller-supplied identifier selected a record, and the handler never related it to the
caller's identity.* The same policy catches both operations, is satisfied by
`order.userId !== req.user.id`, and leaves a query scoped by `req.user.id` alone. Every
route in that corpus applies `requireAuth` — authentication is present, authorization is
not, and a tool that treats an auth middleware as sufficient finds nothing.

Channels are narrowed by **receiver** where it matters: `.json()` counts only when the
object it is called on traces back to the handler's response parameter, through
intermediate calls like `res.status(500)`. Matching a method name alone would flag every
`.json()` in the program.

**Convention analysis.** Infers each route group's access-control convention from the group
itself and reports the members that deviate, with the population as the evidence:

```
[MEDIUM] Inconsistent access control (CWE-284)  <inferred expectation>
  requireAuth is not applied here, but is applied by most comparable entry points
  entry: DELETE /api/orders/:id at orders.ts:16:1
  evidence: 4 of 5 comparable entry points apply requireAuth
```

Detection does not depend on recognizing the control. A team's own `requireTenantScope`
wrapper written last week is as good a signal as a framework guard, because what is being
compared is what peers share — which is why this keeps working on in-house abstractions
that no rule list will ever contain. Because the expectation is *inferred* rather than
declared, these findings never fail a build (ADR-010).

```
make setup && make scan     # lower the fixture, then analyze it
make bench                  # score every corpus
```

**Declared policy states facts, never verdicts.** There is no suppression list, no
ignore-by-rule-id, no baseline-by-line-number, and unknown keys are rejected by the loader
so the rule is enforced rather than documented (ADR-013):

```jsonc
{ "match": { "pathPrefix": "/api/health" },
  "publicByDesign": true,
  "reason": "liveness probe; reached by the load balancer before auth" }
```

A team that wants output to stop must state the property that makes it not a defect — and
that statement then covers every future instance, including routes nobody has written yet.
A declaration without a stated reason is rejected: a rationale is what separates a fact
about the application from a waiver.

Declarations cover what code cannot answer. Whether an endpoint's *purpose* is to establish
identity — login, registration — is one: selecting a record by caller-supplied input is only
an ownership question once there is an owner, and nothing in the source distinguishes a
login from an unauthenticated data endpoint. Whether `auth.required` performs authentication
is another; the team knows, and guessing from spelling is the failure mode this project
exists to avoid. A policy names the property that exempts it, so the engine never learns
what "registration" means — only that a judgement can be exempted.

On the real RealWorld API, a fifteen-line policy takes the ownership analysis from three
false positives to clean, and turns an inferred convention into an enforced requirement
across eleven routes.

The effects are always visible. A suppressed inference is reported with the declaration
that silenced it, and a declaration matching no entry point is reported as **unchecked** —
because a stated requirement nothing was checked against is not a satisfied one:

```
  UNCHECKED declaration "/api/billing*" matched no entry point (not built yet; stated
    now so it is enforced the day it lands)
  suppressed on GET /api/health: requireAuth — declared "/api/health*" (liveness probe...)

[GATING]   Declared control missing (CWE-284)  <declared expectation>
[advisory] Inconsistent access control (CWE-284)  <inferred expectation>
```

**Validated against code nobody wrote for it.** Running the engine on real Express
repositories (OWASP NodeGoat, the RealWorld reference API) found seven defects that eight
hand-written corpora never could — each now a regression case:

| Defect | Effect |
|---|---|
| Destructuring bound nothing | taint died at `const { slug } = req.params` |
| Destructuring lost its path | `const { body: { target } } = req` matched no source |
| Shorthand properties | taint died at `{ slug }` — needs the checker's value accessor |
| Object spread | taint died at `{ ...base }` |
| Property-access middleware | `auth.required` invisible; 20 routes read `controls: none` |
| Property-access handlers | NodeGoat: **zero** entry points enumerated |
| Non-null assertion in a chain | `req.auth?.user!.id` truncated, hiding a real ownership guard |
| CommonJS `require()` unread | no Express binding, so **no route in any classic Node app** |
| Unresolvable handler dropped the route | `controller.register` via CommonJS deleted the entry point entirely |
| Router arriving as a parameter | `module.exports = (app) => { app.get(...) }` invisible |
| Bare-name Python decorators | `@expose("/path")` invisible — 106 uses in one repo |

The last one is the instructive case: a purely syntactic gap turned a correctly-guarded
handler into a **false positive**. Fixing it removed two of six findings on the real repo.

A later batch across **28 repositories** — Express, NestJS, Flask, FastAPI, Flask-AppBuilder,
deliberately-vulnerable apps and large production codebases — found that **18 of 28
enumerated zero entry points**. Robustness was never the issue: all 28 lowered with no
crashes, no parse failures and no timeouts, the largest (6,108 functions) in 7s. The engine
was simply blind. After the fixes: **19 of 28 with a surface, 778 entry points against 158**,
and eight of the nine remaining zeros are correct — a CLI, a framework's own implementation,
and libraries that register no routes.

Notably, Python outperformed TypeScript on recognition, which is the opposite of where the
engineering had gone: one uniform decorator beats a dozen registration idioms.

**Measured, not asserted.** 93 corpora are scored on every test run — vulnerable, safe,
and shape-regression — and a test fails if one is lowered but not scored. A sample:

| corpus | precision | recall | |
|---|---|---|---|
| `express-command-injection` | 1.00 | 1.00 | interprocedural, cross-module |
| `express-async` | 1.00 | 1.00 | await, `.then()`, `forEach` callback |
| `clean-express` | 1.00 | — | 0 findings on safe code |
| `express-authz` | — | — | 1 convention deviation, 0 spurious |
| `express-error-leak` | 1.00 | 1.00 | error detail to response; logging and non-response `.json()` clean |
| `express-webhook-leak` | 1.00 | 1.00 | generalization: unenumerated defect class, channel description only |
| `express-idor` | 1.00 | 1.00 | missing ownership; comparison and actor-scoped query clean |
| `flask-command-injection` | 1.00 | 1.00 | generalization: second language, same policies |

On the real RealWorld API the ownership analysis reported three findings, none of them true
positives — all authentication lookups. With those endpoints declared as
identity-establishing, it reports clean, and each exemption is printed with the declaration
and reason that caused it. Undeclared, the same code is judged: the exemption comes from
what the team stated, never from the engine guessing.

A guard is now recognized anywhere on the flow's own path, not only in the function holding
the operation — real services check in the handler and operate in a private helper. The two
false positives that caused are gone. The looser heuristic ("a call carrying actor identity
is presumed to enforce") stays confined to the function performing the operation, because
widening it cleared genuine defects.

The clean corpus is the denominator. Every route in it is safe for a reason a naive taint
engine gets wrong, and it is verified by negative control: disabling the `shell-quote`
sanitizer model makes the engine report one of those routes, which shows the zero is
earned rather than the result of not analyzing the code. These corpora are small; the
numbers describe the fixtures and nothing beyond them.

**Views are read too.** A server-rendered application makes every escaping decision in a
file the language's own compiler has never heard of, so a scanner that reads only the
handler reads the half where nothing is decided. Both frontends read their ecosystem's
templates and record, per interpolation, whether the engine escapes it — and the finding
lands on the template line rather than on the handler that rendered it. `capabilities:`
prints `templates=`, because "no findings in the view layer" and "the view layer was not
opened" are different results.

**Six kinds of judgement, because a weakness is not always a flow.** Taint asks where a
value came from. Convention asks whether an entry point has what its peers have. A call
shape asks what a call was written with — `createHash("md5")` is weak wherever it appears
and nothing has to reach it. A decision asks what a comparison settles. A store asks where
a value was put — `req.session.role = req.body.role` calls nothing and compares nothing. And
the smallest of them asks nothing at all about context: an RSA private key in a constant is
not an argument, not a destination, and nothing reaches it. Bending any of these into a
flow would mean inventing a source for a defect that has none.

**An absence can be the defect, and it is held to a harder standard than a presence.**
Installing an identity into a session is what every login does; doing it without rotating
the session identifier is fixation. A rule like that can only be wrong by being too
confident about silence, so the search for the missing call is deliberately generous —
through the function, the callbacks it hands out, the helpers it calls and its own callers
— and every one of those directions was a false positive on real code before it was added.

**A function that returns what it was given returns it only to the callers that gave it
something.** Interprocedural taint is not fully context-sensitive — that is a much larger
thing — but the cheapest half of it is here: when a tainted value is returned, the call
sites that receive it are the ones that passed something tainted in, rather than all of
them. Without that, one route handing a role to a shared helper taints every other caller
of that helper and everything computed from the answer; measured on one production
repository it produced 118 findings from a single route. Taint that arises INSIDE a
function — it read a request global, it opened a file — still belongs to every caller and
is untouched.

What remains context-insensitive is a value that reaches a callee through a parameter and
comes back changed several frames later. That is why several rules ask not only whether a
value is classified but whether it is the classified thing ITSELF: a password's own length,
rather than the length of something a password was once involved in producing.

**What it does not do.** A dozen data classes and several dozen channels; two frameworks,
two languages. The remaining code surface is the set of **matching strategies** — how a value
acquires a class, and how a call site is recognized as a channel. Those are still Go, and
shrinking that set is the standing generalization work; classes, channels, and policies
themselves are data.

The Python frontend uses the stdlib `ast` module rather than a real type checker, which
ADR-002 treats as a temporary state: upgrading it to pyright is a frontend change and
nothing else. `typeChecker` is currently declared by frontends but required by no analysis,
so nothing enforces its accuracy yet.

Control detection establishes that a control is **present**, not that it **dominates** the
sensitive operation — a guard inside a skippable branch looks the same as one that always
runs, which needs a CFG. Middleware is enumerated but its ordering and path scoping are not
modeled. Requirements that cannot be derived or inferred are simply unchecked — though the policy schema now covers entry-point
controls, so that gap is narrowing. Declarations select by path prefix, group, and method
only. No diff-scoping, no baseline, no stable fingerprints.

The ownership judgement distinguishes a check that *gates* the handler from one that merely
precedes it, but two loosenesses remain: a call that receives actor identity is presumed to
enforce (an assertion helper that only records would count), and a guard placed after a
destructive operation in the same block still counts, which needs intra-block ordering.
Surface control detection still establishes presence only — the blocks exist now, so that
is wiring rather than new IR. Loops and try/catch are lowered as straight-line code, which
can only under-report. No
diff-scoping, no baseline, no stable fingerprints, no caching, no rule format — framework
knowledge is still compiled in rather than declarative. Taint analysis is
context-insensitive, so a function's parameter carries the union of taint from all its call
sites; this can over-report and will need call-site cloning.

The architectural decisions this skeleton is built to honor are recorded in
[docs/DESIGN-DECISIONS.md](docs/DESIGN-DECISIONS.md).

## What the Tool Claims, and What It Declines to Claim

Three taxonomies, each doing the job it is good at (ADR-007): **CWE** is the identity of a
finding, **ASVS** is what gets asserted, and the **OWASP Top 10** is a rollup *derived* from
the CWE on the way out — never authored on a rule, because stamping a category on each rule
is how tools imply uniform coverage across all ten while their real coverage sits in two.

Every scan ends with a coverage map that deliberately lists what the tool **cannot** check:

```
coverage (OWASP ASVS 5.0.0 requirements this build knows about)
  1 violated, 3 satisfied, 0 not evaluated, 2 out of reach for static analysis, 2 not built
  VIOLATED       8.2.2    Data-specific access is restricted to consumers with explicit
                          permissions (IDOR/BOLA) (3 finding(s))
  out of reach   8.1.1    Authorization documentation defines rules for function-level and
                          data-specific access
                          the intended entitlements are not in the code; this is what a
                          declared policy supplies (ADR-011)
  not built      1.2.4    Database queries use parameterized queries, ORMs, or entity frameworks
                          the engine supports this shape; no SQL channels are described yet

  OWASP Top 10:2025 rollup (derived from CWE):
    A01:2025 Broken Access Control     3 finding(s)  [CWE-639]
```

Four states, and the distinctions are the point. **Out of reach** means no static analysis
can decide it. **Not built** means it is decidable and we have not done it. **Not evaluated**
means the asserting analysis did not run on this codebase — a requirement whose check was
skipped never reads as satisfied, which is the same rule that governs capabilities
(ADR-003). A CWE with no category mapping is reported as **unmapped** rather than defaulted
into one.

The report names the **editions** it maps against, because both taxonomies renumber between
releases: the Top 10 reshuffled its categories in 2025, and ASVS 5.0 replaced the 4.0
chapter structure entirely. Assignments were verified against the published per-category CWE
lists and the ASVS 5.0.0 requirement text.

### The CWE ledger

The same honesty runs one level deeper. The engine carries the **whole published CWE
catalogue** and states, for every entry in it, what this build claims and why:

```
  asserts 93 of 313 weaknesses a rule could be written for (29.7%)
  and 28 more are subsumed: a rule above them catches them, because
  what distinguishes them is a detail the analysis never looks at
```

The denominator is the honest one. It excludes deprecated entries, pillars and classes with
no code shape, and weaknesses specific to a language this build has no frontend for — and it
does **not** shrink when something turns out to be hard, because a denominator that moves
whenever the work looks difficult is not one anybody should trust. It grows by one only when
a rule is written for a weakness the catalogue itself calls undecidable, which has happened
twice and cost a working rule and a fixture each time.

Every one of the 313 says something specific. A test fails the build if any entry falls back
to "no rule has been written for it", because a coverage map is only worth reading if it
distinguishes a weakness this engine could catch tomorrow from one no analysis of source will
ever decide. The declines that were measured carry their numbers: 968 empty catch blocks,
5001 generic catches, 162 path comparisons, 79 of 142 outbound calls with no timeout, 3
route-scoped logging middlewares in 6,390 entry points. Those numbers are the useful part —
they say which gaps are waiting for a discriminator nobody has thought of yet, and which are
closed for a reason.

Weakness identity comes from the **channel**, not the policy. One judgement — *a caller must
not choose what an interpreter executes* — covers both `exec()` and `execFile()`, but
choosing what a shell runs is CWE-78 and choosing which executable runs is CWE-73, and those
roll up to different Top 10 categories.

## Relationship to Adjacent Projects

This project is concerned with **producing** high-quality findings from source code. Determining how a finding ranks against everything else competing for an organization's attention — asset context, exposure, business impact — is a different problem, explored separately in `appsec-risk-engine`. The distinction is intentional: an analyzer should be judged on whether its findings are correct and well-explained, and a prioritization system should be judged on whether it directs attention well. Combining the two tends to produce a system that is difficult to evaluate at either.

## Why This Project Is Interesting

The interesting problem in static analysis is not detection but discrimination. Finding every construct that *could* be dangerous is straightforward and produces something no one will read. Determining which ones are actually dangerous in this application, and explaining that conclusion convincingly enough to survive an engineer's skepticism, is where the difficulty lives — and it is a problem that current open source tooling addresses unevenly.

## Current State

This project is early. The architecture is complete end to end and exercised by three
policy families across two languages, but it is not a tool that should be relied on in
place of an established scanner.

What has been measured: 93 corpora in this repository score precision 1.00 and recall
1.00, and a batch run against 28 unmodified open source repositories produced a surface
for 19 of them — 778 entry points — with every finding triaged by hand. Those runs
measured *recall and enumeration*: whether the engine sees an application's real attack
surface, and whether it finds what is there.

A second run against 16 actively-maintained production repositories — 169,604 functions,
2,008 entry points — asked the harder question: what does the engine do to *healthy*
code? It found five defects that no fixture could have, the largest being that 45% of
findings were not attributable to any entry point the engine had enumerated. One
repository produced 81 findings against 6 enumerated entry points, because a framework's
parameter decorators were recognized while its routing decorators were not. Those flows
are real, but they are not assertions about a mapped attack surface, and they are now
reported as such and never gate.

Acting on those measurements took the same corpus from **207 findings with 17 gating to
14 with none gating** — 0.7 findings per 100 entry points — while fixture precision and
recall stayed at 1.00 throughout.

Almost none of it was a precision problem in the dataflow. The engine was not tracking
data badly; it had no word for the thing the code was using. A policy that can only be
satisfied by relating a record selector to the caller's identity was being applied to
frameworks where identity is injected through an application-defined decorator, so it
could not be satisfied by any code however careful. It now reports that it cannot judge,
and the frontend learned to read those decorators — not by matching names that sound like
identity, but by asking whether what the decorator pulls off the request is part of the
HTTP request at all. Anything else was attached by server-side code, and the caller could
not have chosen it. One codebase in the set calls its tenant a `workspace`; a list of
likely names would have missed all six of its correctly scoped operations.

**It runs at pipeline speed.** Lowering a 48,000-function monorepo took 78 seconds until
profiling showed the frontend was accidentally quadratic: every source file scanned the
whole program's function map, asking each entry which file it belonged to, through a call
that answers by walking a parent chain. Grouping once first took the worst case from 170
seconds to 20. A `-changed` flag scopes what may gate to the files a change touched,
following the whole evidence path rather than just the sink, and never hides what it does
not gate on.

**SQL injection is asserted**, and the way it became precise is the clearest illustration
of the design. A parameterized query needs no special case: the channel names the argument
that is *interpreted*, so untrusted data arriving in the params cannot match. But the first
run produced 622 findings on healthy code, 606 of them from `.execute` -- in one codebase
every use case is `usecase.execute(command)`. The fix was not a longer list of names. SQL
injection means untrusted input was *composed into a statement*, a command object is
constructed rather than composed, and asking that question took 622 findings to 16 while
keeping every real one.

Every remaining finding has been triaged by hand: one true positive, one worth a human
look, five disputed error-exposure findings, and seven false — five of those being the
declared-policy mechanism working as designed rather than the analysis being wrong.

**A measurement that only reduces findings will happily reduce them to zero.** So the
same treatment was applied in the other direction, against seven applications built to be
vulnerable. The first run found almost nothing, and the cause was not coverage: a handler
written as `module.exports.ping = function (req, res)` could not be resolved, so the route
detector filed it as middleware and enumerated the route with no body. The surface still
listed the route and still looked complete, while a textbook
`exec('ping -c 2 ' + req.body.address)` three lines inside it reported clean. Two more of
the same kind followed — element access and constructor arguments were not lowered at all,
so `match(re)[1]` and `new Function(src)` broke every chain that passed through them.

None of those three could have been found by looking at false positives. A false negative
leaves nothing in the report to look at, which is the argument for keeping both corpora.

Coverage remains narrow, and outside it the engine reports nothing at all. That is a
limit of what has been modelled, not evidence that the code is sound — the distinction
ADR-003 exists to preserve.
