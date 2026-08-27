# SAST Engine Design Decisions (ADR)

Load-bearing decisions that are easy to "helpfully" undo in a later review. Most of
these trade short-term simplicity for the property that makes the project worth
building at all — depth per language, with one shared analysis core. A reviewer
optimizing any single file will be tempted to reverse several of them.

**Note on status.** ADR-001 through ADR-008 were recorded before any code existed,
because they are architectural: cheap to honor from the start and expensive to retrofit.
Every ADR here is implemented and enforced by tests.

The mapping data underneath ADR-007 was verified on 2026-08-15 against the published
sources: per-category CWE lists at owasp.org/Top10/2025 and the ASVS 5.0.0 requirement
text in the OWASP/ASVS repository. Editions are named in the report, because both
taxonomies renumber between releases — the Top 10 reshuffled its categories in 2025 and
ASVS 5.0 replaced the 4.0 chapter structure entirely.

---

## ADR-001: The IR is the contract; frontends and core never see each other

**Status:** Accepted (2026-08-10), pre-implementation. Agreed with the product owner.

### Decision
The system has exactly one seam. A **language frontend** parses, resolves, and lowers
a codebase into a normalized **Program IR**. The **core** consumes only that IR and
performs all analysis: call-graph traversal, taint propagation, path feasibility,
evidence construction, fingerprinting, gate policy, and output.

A frontend's job ends when the IR is produced. It does not produce findings. The core
does not import a language-specific type, parser, or AST node — not for a special case,
not for a fast path, not "just for TypeScript."

The IR carries:

- **Skeleton** — modules, functions with stable IDs, call-graph edges, per-function CFG,
  dataflow facts (assignment, field access, aliasing)
- **Entry points**, tagged by kind (`http-route`, `server-action`, `queue-consumer`,
  `cli`, `event-handler`, …) as an **open string set**, not a closed enum
- **Annotations** — sources, sinks, sanitizers, and framework guarantees attached to
  IR nodes, contributed by framework models
- **A properties escape hatch** — a language-specific bag, so normalization does not
  flatten what makes a language's semantics interesting
- **Provenance and resolution confidence** on every fact and every call edge
  (`resolved | probable | dynamic-unresolved`)

### Why (do not revert this)
This is the TerraLift `model.Inventory` decision, and it is the reason that project
could add AWS and GCP after Azure without rewriting its analysis. The inventory shape
*is* the interface; every shared phase consumes it unchanged.

The failure mode this prevents is specific and common. A frontend that can emit findings
directly will emit findings directly, because for any single language that is faster and
produces better results *today*. Within two languages, the "shared core" is a thin
formatting layer wrapping N independent analyzers, each with its own precision
characteristics and its own bugs — which is the orchestration architecture we explicitly
rejected, arrived at by drift rather than by decision.

Open string taxonomies matter for the same reason. If `EntryPointKind` is a closed enum
containing the kinds TypeScript needs, then Python's WSGI handlers, Java's servlet
mappings, and Go's `http.HandlerFunc` are each a core change. Constants are conventions
for the built-in frontends; the type is open.

### If you are a future reviewer
An `import` of a language-specific package inside the core is a defect regardless of what
it accomplishes. If the core needs a fact it does not have, the fix is to add that fact
to the IR — where every other frontend can then supply it too — not to reach across the
seam for it.

---

## ADR-002: Per-language compiler frontends, not one polyglot parser

**Status:** Accepted (2026-08-10), pre-implementation. Agreed with the product owner.

### Decision
Each frontend uses **its own language's real compiler or type infrastructure** as its
semantic source: the TypeScript Compiler API for TS/JS, pyright for Python, `go/types`
for Go, JDT/javac for Java, Roslyn for C#. Frontends are not required to share a parsing
technology, and there is no project-wide parser.

Fast, type-free parsers (tree-sitter, SWC, Oxc) are acceptable *within* a frontend for
tasks that genuinely do not need semantics — file triage, lexical prefiltering — but they
are not a substitute for the type layer.

### Why (do not revert this)
This is the entire competitive thesis. Precision in taint analysis depends on resolving a
call site to its actual declaration across files, and on knowing real types at each hop.
A language's own compiler already does that work, correctly, for free.

The alternative — one parser across all languages — is the architecture Semgrep chose, and
it is why Semgrep's open engine is largely confined to single-function scope: a
language-agnostic engine structurally cannot use any language's type system. Joern's
frontends are fuzzy for the same reason. CodeQL made the correct call here and is
license-encumbered. The open position nobody currently occupies is *CodeQL-depth frontends
under a permissive license*, and it is only reachable by paying the per-language cost.

A reviewer will observe — accurately — that tree-sitter everywhere would be faster to
implement, faster at runtime, and would make language #4 a weekend instead of a quarter.
That trade buys breadth by giving away the only thing that makes this tool better than
what already exists for free.

### If you are a future reviewer
"Let's standardize on one parser to simplify the frontends" is a proposal to become a
worse Semgrep. Per-language cost is the moat, not an inefficiency to optimize away.

---

## ADR-003: Capabilities are declared; "not applicable" is never reported as "clean"

**Status:** Accepted (2026-08-10), pre-implementation. Agreed with the product owner.

### Decision
Every frontend declares what it can actually support — whether full type information is
available, whether call resolution is interprocedural, whether it crosses module
boundaries, and which framework models are loaded.

Core analyses that require a capability the frontend lacks report **not applicable**, as
a distinct outcome from *ran and found nothing*. This distinction survives all the way to
the report and to the pipeline's exit status. A scan is never described as clean for an
analysis that never ran.

### Why (do not revert this)
This is TerraLift's `provider.Capabilities`, and the reasoning transfers exactly: a
provider with no IAM plane must report hygiene as "not applicable" rather than "checked,
found nothing."

The risk here is worse than in TerraLift, because in security a silent gap reads as a
passing grade. A weak frontend — an early Python implementation, a language where the type
layer is not wired up yet — will return few findings. Few findings looks like a secure
codebase. Nobody downstream can distinguish "we analyzed this thoroughly and it is fine"
from "we could not analyze this," and the tool's credibility is spent on a claim it never
actually made. Every language added after the first makes this more likely, which is why
the mechanism must exist before the second one lands.

### If you are a future reviewer
"Not applicable" lines in a report are not noise to be cleaned up. They are the tool
declining to make a claim it cannot support. If they are cluttering output, change how
they are *presented*; do not stop emitting them, and never let them collapse into a
pass.

---

## ADR-004: Framework models are declarative data, and a wrong entry is inert

**Status:** Accepted (2026-08-10), pre-implementation. Agreed with the product owner.

### Decision
Framework knowledge — Express, Next.js, NestJS, Django, Spring — is contributed as
**declarative data**, not engine code. A model describes entry points, sources, sinks,
sanitizers, and framework guarantees (JSX escapes; the ORM parameterizes; this middleware
validates) in a shared format that is the same across languages.

Model loading is **permissive**. A stale, wrong, or unrecognized entry is ignored. It
never fails a scan, never aborts loading of the remaining entries, and never corrupts the
IR. The worst outcome of a bad model entry is a missed finding or a false positive
attributable to that entry.

### Why (do not revert this)
This is the property that makes `awsTypeToTF` maintainable: a wrong or stale entry is
inert — it simply will not match a real resource. That is what allows coverage to be
expanded incrementally, by contributors, without a full verification pass gating every
addition.

Framework coverage is the long tail of this project and it never ends. Frameworks are
numerous, they version, and their security-relevant behavior changes between major
releases. If adding a framework requires engine changes, or if a stale entry breaks
scans, then framework support becomes a core-team bottleneck and the tail never gets
covered — which forfeits the precision advantage, since framework semantics are where
precision comes from.

Strict validation is the natural instinct and it is wrong here. A model that fails loudly
on an unknown key means every framework version bump is a broken build for users on the
old version.

### If you are a future reviewer
Do not make model loading strict, and do not move framework logic into the engine because
one framework needed something the format could not express. Extend the format so all
frameworks can express it.

---

## ADR-005: The gate is driven by confidence, not severity

**Status:** Accepted (2026-08-10), pre-implementation. Agreed with the product owner.

### Decision
Findings are tiered by **analysis confidence**, derived from the resolution quality of the
call edges along the reported path. A finding whose path is fully resolved is high
confidence. A finding whose path crosses a `dynamic-unresolved` edge is lower confidence
regardless of the seriousness of the vulnerability class.

Pipeline gate policy is expressed over confidence and vulnerability class as an explicit
decision about what blocks. It is **not** a severity threshold.

### Why (do not revert this)
Severity is an intrinsic property of a vulnerability class, assigned by someone who has
never seen this codebase. It says nothing about whether *this* result is correct. Gating
on it means blocking builds on high-severity guesses and ignoring low-severity certainties
— which teaches a team that the gate is unreliable, and the gate is then moved to advisory
and stops mattering. That is the trust spiral the whole project exists to avoid.

Confidence is a property the engine actually knows, because it is a direct consequence of
how well the call graph resolved. Gating on it means a blocked build is always defensible,
which is the only condition under which a security gate survives contact with a
development team.

### If you are a future reviewer
Every other tool in this space gates on severity, so "add a severity threshold to the
gate" will be requested, repeatedly, by people reasoning from that convention. Severity
may be *reported* and may inform prioritization downstream. It must not be what decides
whether the build fails.

---

## ADR-006: A finding must carry its evidence, or it is demoted

**Status:** Accepted (2026-08-10), pre-implementation. Agreed with the product owner.

### Decision
Every finding ships with a reviewable justification: the path from entry point to
dangerous operation, hop by hop, and the sanitizers considered along with why each was
judged insufficient for that sink's context. Sanitizer adequacy is evaluated **against the
sink's context** — an encoder that is correct for a URL sink does not clear taint for an
HTML sink.

A result the engine cannot explain this way is not promoted to a gating finding. It may be
recorded at a lower tier; it does not block, and it is not presented with the same
authority as a result that can show its work.

### Why (do not revert this)
The reason static analysis is distrusted is that a finding is usually an assertion with a
line number, which pushes the entire burden of verification onto the reader. Evidence is
what makes triage cheap, and cheap triage is what keeps the tool switched on.

The instinct to revert this is a recall argument: *we found something suspicious, surely
reporting it weakly is better than not reporting it.* At scale it is not. Unexplainable
findings are the ones most likely to be wrong, most expensive to triage, and most
corrosive to trust — and they arrive in the volume that trains engineers to ignore the
explainable ones sitting next to them.

### If you are a future reviewer
Do not raise unexplainable results to gating status to improve a recall benchmark. If a
class of real vulnerabilities cannot be evidenced, that is a signal to improve the
frontend's resolution or the framework model — the places where the missing information
actually lives.

---

## ADR-007: CWE is the identity, ASVS is the assertion, Top 10 is the rollup

**Status:** Accepted (2026-08-10), pre-implementation. Agreed with the product owner.

### Decision
Three OWASP-adjacent taxonomies, each used for what it is actually good at:

- **CWE** is the internal identity of every finding — precise, stable, and the thing
  everything else maps from.
- **ASVS** is what the tool asserts against. Its requirements are discrete and verifiable,
  which makes them a real target for analysis.
- **The OWASP Top 10** is a **derived reporting rollup**, computed from the CWE mapping.
  It is never authored directly on a rule.

Coverage is published honestly: which requirements are asserted, which are partially
covered, and which are out of reach for static analysis entirely.

### Why (do not revert this)
The Top 10 is an awareness document, not a test specification. Ten deliberately coarse
categories, several of which — insecure design most obviously — are not statically
decidable. Authoring rules directly against it produces the industry-standard dishonesty:
a category label stamped on each rule, implying uniform coverage across all ten when
coverage is in fact concentrated in the injection-shaped categories and absent elsewhere.

Deriving the rollup from CWE means the Top 10 view stays correct across editions, since a
new edition is a remapping rather than a re-labeling of every rule.

### If you are a future reviewer
Do not add a `owasp_top10:` field to a rule definition. It belongs in the CWE mapping
table, computed on the way out. And do not remove the coverage map because it advertises
gaps — stating what the tool cannot do is what makes its positive claims worth believing.

---

## ADR-008: The second language lands before the first one is broadened

**Status:** Accepted (2026-08-10), pre-implementation. Agreed with the product owner.

### Decision
TypeScript/Node is the validation language, not the product. Once TS is working end to end
— IR, taint propagation, evidence, one framework model, a handful of vulnerability classes
— the next work is a **second language frontend**, before TypeScript coverage is broadened
to more frameworks, more classes, or more rules.

### Why (do not revert this)
An IR validated against exactly one language is that language's data model wearing a
costume. Nobody discovers which parts of it were TypeScript-shaped until a second frontend
tries to lower into it, and by then every assumption has downstream code depending on it.

TerraLift's inventory model is durable because it had to serve three clouds; the abstraction
was tested by the second and third provider, not asserted from the first. The equivalent
test here is a language with genuinely different semantics — Python stresses imports,
decorators, and duck typing; Java/Spring stresses interfaces, generics, and DI-container
indirection.

The pressure to defer this will be constant and reasonable-sounding, because broadening
TypeScript always has a nearer-term payoff than proving the abstraction. That is exactly
why it is written down here.

### If you are a future reviewer
Deferring the second frontend to ship more TypeScript rules is the decision that quietly
converts this project into a TypeScript SAST tool with an unused abstraction layer.

---

## ADR-009: Findings are assertions over an enumerated surface, not pattern matches

**Status:** Accepted (2026-08-10). Agreed with the product owner.

### Decision
The engine's primary output is a **surface model**, not a finding list. The surface is an
enumeration of the application's attack surface — every entry point, each annotated with
the facts that matter about it:

```
entry point → authn?  authz?  middleware chain  reaches which sinks
              loads by user-supplied id?  returns privileged data?  writes?
```

Findings are **derived assertions over that model**. "This route has no authorization
decision on any path" is a statement about the surface, not a pattern found in text.

Pattern matching remains available, but it is a detector that contributes facts to the
surface. It is never the unit of analysis.

### Why (do not revert this)
The most valuable findings in a real security review are statements about **absence**, and
absence is not expressible as a pattern. Reviewing the last deep-dive of a production
estate, the single highest-impact finding — an unauthenticated endpoint that three
independent reviewers flagged — is invisible to every pattern-based tool, because there is
no bad code anywhere in it. The defect is that something expected is missing.

A pattern engine can only answer "is this dangerous thing present?" An enumerate-and-assert
engine answers "for every element of the surface, does the required property hold?" That is
the question a human reviewer actually asks, and it is the question that reaches OWASP A01
— the category that dominates real incidents and that conventional static analysis does not
address at all.

This also changes what a scan means. A pattern scan that reports nothing might have found
nothing or might have looked at nothing. A surface model is inspectable: an operator can
read the enumerated entry points and see whether the tool understood their application
before trusting any conclusion it drew.

### If you are a future reviewer
"Just add a rule for it" is the reflex that undoes this. When a new finding class is
requested, the first question is *what property of the surface is being asserted*, and
whether the surface carries the facts needed to assert it. If it does not, the fix is to
enrich the surface — where every other analysis can then use those facts — not to add a
pattern that answers this one case in isolation.

Deleting the surface from the output because "users only want findings" removes the only
part of the report that shows what was actually examined.

---

## ADR-010: The codebase's own conventions are a rule source

**Status:** Accepted (2026-08-10). Agreed with the product owner.

### Decision
Expected properties may be **inferred from the population** rather than declared globally.
Within a group of comparable entry points, a control present on a strong majority of peers
is treated as expected, and the members lacking it are reported as deviations — with the
population itself as the evidence:

> 17 of 19 routes in this module apply `requireAuth`; these 2 do not.

Detection deliberately does **not** depend on knowing what a control does. A route-level
middleware reference shared by a group's peers is a signal regardless of its name, its
implementation, or whether the engine has ever seen it before.

### Why (do not revert this)
This is what makes a review read as a review rather than a checklist, and it is the pass
that finds the bugs that matter, because real defects are usually inconsistencies rather
than universal absences. Teams that authenticate nothing know it. Teams that authenticate
nineteen routes out of twenty do not.

It also self-tunes. A global list of known authentication middleware is stale the moment a
team writes their own wrapper, and maintaining that list across every framework is exactly
the treadmill that makes tools decay. Inference from peers requires no list, works on
in-house abstractions the moment they exist, and improves as a codebase grows.

Because the expectation is *inferred*, these findings are capped below the gating tier
(ADR-005). The engine resolved the fact reliably — the middleware genuinely is not there —
but the requirement is a guess about intent. Inferred expectations inform; declared
expectations (ADR-011) gate.

### If you are a future reviewer
Replacing convention inference with a hardcoded list of known auth functions looks like a
precision improvement and is a capability regression. Keep the list, if one exists, as an
*additional* detector; do not make it the source of truth. And do not promote convention
findings to gating status to make them feel more serious — the confidence cap is a
statement about what the engine actually knows.

---

## ADR-011: What cannot be derived is declared, never guessed

**Status:** Accepted (2026-08-10). Agreed with the product owner.

### Decision
Properties that cannot be recovered from code — business rules, environment boundaries,
data classification, which routes are intentionally public, whether a system needs a
dead-man's switch — are supplied by the team as an explicit policy, or they are not checked
at all. The engine does not infer intent from names, comments, or heuristics dressed up as
analysis.

Every requirement therefore has a stated origin: **derived** (a fact about the code),
**inferred** (ADR-010, a fact about the population), or **declared** (a policy the team
wrote). That origin is carried on the finding.

### Why (do not revert this)
Roughly a quarter of the findings in a real deep-dive are of this kind: nothing in the code
is wrong, an expectation is simply absent. The temptation is to approximate them with
naming heuristics — treat `/admin/*` as requiring elevation, treat a field called `ssn` as
sensitive. That produces confident-sounding output derived from spelling, which is the
failure mode this project exists to avoid, and it is unfixable once shipped because users
cannot tell which findings rest on real analysis.

Asking the team to declare intent once is not a weakness of the design. It is the only
honest way to reach the categories that are genuinely about design rather than code, and a
declared expectation is stronger than an inferred one — it is the one case where blocking a
build is unambiguously defensible.

### If you are a future reviewer
Do not close a coverage gap by inventing a heuristic for something the code does not state.
Add it to the policy schema instead, and report it as unchecked until someone declares it.
An unchecked requirement reported honestly is worth more than a guessed one reported
confidently.

---

## ADR-012: Encode the reasoning, not the finding

**Status:** Accepted (2026-08-10). Agreed with the product owner, correcting an earlier
implementation that failed this test.

### Decision
An analysis must encode **why something is a defect**, in terms general enough that the
same rules find instances nobody had in mind when they were written. Rules describe
properties — what class of data this is, what kind of channel that is, which pairings are
forbidden — never a specific defect's shape.

The test is falsifiable and should be applied to every rule added:

> Could this rule set find a *different* instance of the same class of problem, one that
> was not being looked at when the rule was written? If catching the next instance requires
> writing another rule, the logic was not captured — only the example was.

Applied to information exposure, the reasoning is not "a catch binding must not reach
`res.json`." It is:

> a value carries a data class; a channel has a visibility; policy forbids that pairing;
> no transform on the path changed either.

That formulation reaches credentials in a log, internal hostnames in an error body, PII in
an outbound webhook, and cross-tenant records in a response — none of which anyone
enumerated — because each is the same three-part judgement applied to different values.

### Why (do not revert this)
Rules written from remembered findings produce a tool that is excellent at re-finding what
has already been found. That is the failure mode of every checklist scanner: coverage looks
broad because the rule count is high, while the actual reasoning is absent, so the first
variant that does not match the remembered shape passes silently. The tool then reports
clean on a codebase it never really examined — which is the worst outcome available, worse
than reporting nothing.

There is a specific temptation here. A real review produces a concrete list, and turning
each item into a rule feels like progress and demonstrates immediate value. It is the
wrong unit of work. The list is *evidence about what reasoning is worth mechanizing*, not
a specification. Each finding should be interrogated for the general judgement that
produced it, and that judgement is what gets built.

Applying the test also exposes where a design has stalled. If a new instance needs a new
matching *strategy* rather than new data, that is a real and reportable boundary — the
honest response is to name the strategies that exist and treat the list as the thing to
generalize next, not to keep adding strategies one finding at a time.

### If you are a future reviewer
When a rule is added, ask what property it asserts. If the answer names a specific
function, a specific framework call, or a specific defect from a specific report, it is a
finding wearing a rule's clothing. Rules name classes, channels, contexts, and policies;
the specific symbols that belong to each are data underneath them.

A rule whose only justification is "we saw this once" belongs in a corpus as a test case,
not in the model as logic.

---

## ADR-013: The policy file declares intent, never verdicts

**Status:** Accepted (2026-08-15). Agreed with the product owner.

### Decision
The policy file states **facts about the application**. It cannot state conclusions about
findings. There is no suppression list, no ignore-by-rule-id, no baseline-by-line-number,
and no `# nosec`-style inline escape.

Permitted:

```jsonc
{ "match": { "pathPrefix": "/api/public" },
  "publicByDesign": true,
  "reason": "marketing pages; no data access" }
```

Not permitted, and deliberately not expressible:

```jsonc
{ "ignore": "CWE-639", "file": "app.ts", "line": 41 }
```

A team that wants a finding to stop appearing must state the property that makes it not a
defect. That statement then applies to every future instance of the same property,
including ones nobody has seen yet.

### Why (do not revert this)
A suppression list is finding-shaped, and finding-shaped configuration decays in a
specific way: it accumulates exceptions rather than knowledge. After a year, the file
records that eleven particular lines were once waived, by people who have left, for
reasons nobody wrote down — and it silences the *next* instance of nothing, because a
line number describes one occurrence and no property at all.

A declaration accumulates the opposite. "These routes are public by design" is a fact that
keeps paying: it suppresses today's noise, it suppresses the same noise on a route added
next quarter, and it is reviewable — a security engineer reading the policy file learns
what the team believes about their own application, which is exactly the artifact that
does not otherwise exist.

This also protects the reasoning built everywhere else (ADR-012). If findings can be
waived individually, the pressure to make analyses *correct* disappears — every false
positive has a cheap local fix, so nobody fixes the model. Removing that escape hatch
keeps the cost of a wrong judgement where it belongs.

The temptation to revert is real and will be well-argued: users will ask for suppression,
competitors ship it, and a stubborn false positive with no waiver is genuinely painful.
The answer to a false positive is to state the property that makes it wrong, or to fix the
analysis — both of which improve the tool. A waiver improves nothing.

### If you are a future reviewer
"Add an ignore list, users need an escape hatch" is the request that converts this from a
security model into a linter with a `.ignore` file. If a real defect class cannot be
expressed as a declared property, that is a gap in the policy schema and should be closed
there — by adding a property teams can declare, not by adding a way to silence output.

Declared requirements **gate** a build; inferred ones (ADR-010) never do. That asymmetry
is the point: a team that wrote down what it expects has earned an enforceable claim.

---

## ADR-014: A baseline records what was there; it never says anything is acceptable

**Status:** Accepted (2026-08-23).

### Decision
A baseline file records the **fingerprints** of findings present at a moment in time. A
finding whose fingerprint is in the baseline is still reported, still counted, still
carries its full evidence, and is labelled as recorded. The single thing it does not do
is gate the build.

The fingerprint is built from what a finding *is* — the policy, the weakness, the entry
point, the file and function holding the operation, the symbol reached, and what the data
was. It deliberately excludes the line number.

Nothing about a baseline is expressible in the policy file, and nothing in the policy file
can reference a fingerprint. The two mechanisms answer different questions and are kept in
different files on purpose.

### Why (do not revert this)
The obvious "simplification" is to stop printing baselined findings. Do not. That single
change turns this into the suppression list ADR-013 exists to prevent, with worse
properties: a suppression list at least names what it is suppressing, while a hidden
baseline means the report claims a clean codebase that the engine knows is not clean. The
first person to regenerate the file after a bad merge would silently bless a real defect,
and nothing in the output would say so.

The distinction is a real one and worth holding. **A declaration says "this is not a
defect, and here is the property that makes it so"** — a claim about the application that
keeps paying on code nobody has written yet. **A baseline says "this was already here on
Tuesday"** — a claim about history that makes no assertion at all. Only the first belongs
in the policy file, and only the first should ever make a finding disappear.

Excluding the line number from the fingerprint is not a detail. If adding an import above
a defect changed its identity, every commit touching a file would re-report everything in
it, and a team would learn within a day that the "new findings" list means nothing. That
was the prerequisite for the whole mechanism, and it is why paths in the IR must be
root-relative (a fingerprint computed from an absolute path differs between a developer's
machine and a build agent, which produces the same failure in a form that is much harder
to see).

### If you are a future reviewer
Check that a baselined finding still appears in the report with its evidence and a
`in baseline:` marker, that the coverage table still reports its requirement as VIOLATED,
and that `-write-baseline` records **every** finding rather than only the gating ones. A
baseline holding only today's gating findings quietly promotes the rest into "new" on the
first run that raises their confidence.

---

## ADR-015: A rule is measured on correct code before it is written down

**Status:** Accepted (2026-08-25). Recorded after the fourth rule in a row was killed or
reshaped by its own measurement.

### Decision
Before a rule is added, count how many times its shape occurs in the **clean corpus** —
production applications that are broadly correct. Every match there is presumed a false
positive until adjudicated otherwise. The count decides one of four outcomes:

- **Build it.** The shape is rare in correct code and the matches that exist are real.
- **Reshape it.** The count exposes the wrong discriminator, and a different one is
  available. This is the most common outcome and the most valuable.
- **Move the judgement.** The call cannot answer the question but a SINK can. A property
  recorded at the source and judged where the value lands is a different rule with the
  same subject.
- **Decline it, with the number.** Record the count in the coverage map. "We decided not
  to" is only an honest answer when it says what the decision was based on.

The measurement happens **before** the rule exists, using a query over the lowered IR or
the corpus source. Writing the rule first and measuring afterwards produces a strong
attachment to a rule that should be deleted.

### Why (do not revert this)
Every rule looks reasonable in the abstract. The following all looked reasonable and all
were wrong, and only counting said so:

| Rule as first conceived | Clean-corpus matches | What they were |
|---|---|---|
| Log injection: caller data into a log | 11,164 | almost entirely token counts and IDs |
| Hardcoded password: any call with a `password` option | 265 | test helpers and assertions |
| Insufficient entropy: fewer than 16 random bytes | 77 | unique suffixes, colours, table names, slugs |
| Argument injection: an argument array to `execFile` | — | the *recommended fix* for command injection |
| Missing log middleware as a convention | 3 of 6390 entry points | no population to infer from |

The last two matter most. A rule that reports the recommended fix teaches users that the
tool is wrong about the thing they just did correctly, and they are right to stop reading
it. A convention rule with no population is not a strict rule — it is a rule that will
never fire, which is worse, because it occupies a line in the coverage map that claims
otherwise.

Counting first also converts a dead end into a result. The entropy rule failed as a call
shape and succeeded as a classification judged at a cookie: the same subject, a different
place to ask, and zero clean-corpus findings instead of 77. Nothing about the second
version would have been discovered by iterating on the first.

There is a second-order effect worth naming. A project that measures before building
accumulates a coverage map whose declines carry numbers, and those numbers are the most
useful thing in it: they tell the next person which weaknesses are genuinely out of reach
and which are merely waiting for a discriminator nobody has thought of. A map of
undifferentiated "not built" entries tells them nothing.

### If you are a future reviewer
For any rule added, ask where the measurement is. It should be in the commit message as a
count, and in the coverage map's reason where the count changed the design. A rule whose
clean-corpus behaviour is unknown has not been finished, however good its fixture looks —
a fixture proves the rule fires on the case it was written for, which is the one thing
never in doubt.

Ask also whether a decline names its number. A decline that says "too noisy" without
saying how noisy is an opinion, and the next person will have to re-measure it to find
out whether it is still true.

---

## ADR-016: An analysis kind exists when a weakness cannot be bent into an existing one

**Status:** accepted

**Context.** The engine began with one kind of judgement — a flow from a source to a sink
— because that is what a taint analyser is. Five more exist now, and each was added for
the same reason: a real weakness had no flow in it, and expressing it as one would have
meant inventing a source for a defect that has none.

- **FLOW** — where a value came from. `exec(req.query.host)`.
- **CONVENTION** — whether an entry point has what its peers have. Nothing is *there* to
  match; the defect is an absence, and the population is the only evidence.
- **CALL SHAPE** — what a call was written with. `createHash("md5")` is weak wherever it
  appears; nothing reaches it and no caller controls anything.
- **DECISION** — what a comparison settles. `if (token == expected)` in variable time, a
  password policy of one character, an origin matched with `startsWith`.
- **STORE** — where a value was put. `req.session.role = req.body.role` calls nothing and
  compares nothing: the caller's claim is simply moved to the far side of a boundary.
- **LITERAL** — a value whose own shape is the defect. An RSA private key in a constant is
  not an argument, not a destination, and nothing reaches it.

**Decision.** A new kind is justified when a weakness cannot be *stated* in an existing
one without lying about the program. It is not justified by a rule being awkward to write,
by a rule needing a new field, or by a family of weaknesses being large.

The test is whether the existing kind would have to be given a fact it does not have. A
private key in a constant has no call for CALL SHAPE to read and no write for STORE to
watch; making STORE report it would mean inventing a destination. That is a new kind. A
rule that needs to know whether the receiver was projected is not — that is a field.

**Consequence.** Every kind is one more surface to be wrong on, and the cost is paid in
the same currency each time: each one needs its own measurement on correct code before it
ships (ADR-015), its own fixture with negatives drawn from real programs, and its own
answer to what it is silent about. LITERAL is silent about any secret with no recognisable
shape, and says so.

The kinds do not compose and are not meant to. Two of them reporting the same line is not
a duplicate: `req.session.role = req.body.role` is a trust-boundary violation AND a login
that does not rotate the session identifier, neither fix repairs the other, and a reader
who is told only one of them has been told the smaller half.

**How to tell if this is being applied.** Ask what fact the new kind reads that no existing
kind can reach. If the answer is a field on an existing rule, it is a field.

---

## ADR-017: The engine enumerates everything it found and reports the part that is a defect

**Status:** Accepted (2026-08-27).

### Decision
A run produces two sets, and they are named:

- **enumerated** — every finding the analyses produced, with its whole evidence path.
- **reported** — the subset that is a defect in the application somebody is being asked
  to defend.

A finding leaves the reported set for exactly three reasons, all of them facts a frontend
lowered: it is in a test module (`ir.Module.IsTest`), it is in code the repository did not
hand-write (`ir.Module.Provenance`), or the value that makes it wrong could only have been
supplied at operator or internal trust (`ir.EntryPoint.Trust`). The judgement is one
function in the policy layer (`policy.Context`), applied to every analysis kind at once in
`scan.Run`, so a rule written next year inherits it without knowing it exists.

Everything else is unchanged. An enumerated finding still prints, with its path, under the
reason it is not reported. It still travels in SARIF, at the level it always had, carrying
`properties.reportable` and `properties.notReportedBecause`. A baseline still records it.
Precision is scored over the reported set; **recall is scored over the enumerated set**,
because an expectation asks whether the engine FOUND the thing.

### Why (do not revert this)
Measured. Across twenty repositories, 12 of the 41 false positives attributed to the eight
worst-scoring rules were one failure repeated across eight unrelated rules: the rule found
exactly the shape it was built to find, in a test fixture, in an example, or on a path only
somebody who already holds the host can walk. Every one of those rules was correct. What
was wrong was the set it published into.

Re-scored over the ten repositories of batch 2, 86 enumerated findings became 55 reported.
The 31 are 20 in test modules, 6 in `examples/`, and 5 reached only through a management
command. Not one of them left the output, and the gating count did not move by one on any
of the ten — which is the check that says this changed what the engine PUBLISHES rather
than what it believes.

The distinction it is easy to collapse is between this and a suppression (ADR-013), and
the difference is that nothing here reads a filename or a rule name. The terms are three
IR facts; a repository that spells its tests differently is answered by the frontend that
knows that ecosystem, and a rule added tomorrow gets the same answer as one added a year
ago. It is also why the answer is a sentence and not a flag: a reader who is not shown a
finding in the list they are reading is owed the reason it is elsewhere.

### If you are a future reviewer
Two ways this goes wrong. The first is scoring recall over the reported set: that turns the
corpora holding the non-HTTP entry-point classes into false negatives and looks like a
precision win. The second is trusting the trust term where it is a proxy for the wrong
question. `Trust` says who can cause the entry point to run, and for a value that a caller
supplied that is also who supplied it — but a weakness whose victim is somebody OTHER than
the caller does not follow that rule. `testdata/secret-file-created-before-chmod` is the
case: a secret file created at the process umask, reachable only from a program start, and
the local user who reads it in the interval is not the operator who started it. It is
enumerated and not reported today, and if a second case like it is measured, the fix is to
ask whether the finding is about a value that crossed the boundary — not to add an
exception for the rule.
