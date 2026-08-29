# Loop issues

What the engine could not say, found by running it against unmodified public repositories.
One entry per distinct defect, not per repository. See `docs/review-loop.md` for how these
are produced and `validation/verdicts.json` for the verdict ledger they are derived from.

Entries are ordered by recurrence count at each batch boundary, and that count is what
decides the order they are fixed in. Six repositories hitting one gap outranks one
repository hitting six.

## A defect here is a task, not a note

**The batch that produced these is not finished until every one of them is closed.** Closed
means fixed with a fixture, or measured and withdrawn with the numbers written down. It does
not mean deferred because the fix looked hard, needed a new seeding strategy, or might have
been noisy: those are guesses, and a guess is not a measurement.

The engine and an independent security review should converge. Every entry below is a place
they did not, and difficulty is what makes an entry interesting rather than what excuses it.

## Kinds

| kind | meaning |
|---|---|
| `MISS-RULE` | a real weakness with no rule for it |
| `MISS-SYMBOL` | the rule exists, the symbol is not in the model |
| `MISS-SURFACE` | the entry point was never enumerated, so nothing downstream was reachable |
| `MISS-FLOW` | source and sink both known, the path did not connect |
| `FALSE-BROAD` | the rule states something too loosely |
| `FALSE-SANITIZER` | a real guard the engine does not recognise |
| `SURFACE-OVER` | routes reported that are not routes |
| `CRASH` | frontend or core failed on real code |
| `NOISE` | correct, and still not worth a person's attention |

## Entry format

```
### <fingerprint>  <KIND>  seen in N repos
**What happened.** <one or two sentences>
**Where.** <repo>@<sha> <path>:<line>
**What the engine should do.** <the actual change, specifically>
**Fixture.** testdata/<name>/ (or: not yet extracted)
**Status.** open | fixed in <commit> | measured and withdrawn: <reason>
```

---

## Open

_Nothing open. Batch 1's sixty-eight defects are closed._

This file is a working list, not an archive. An entry is removed when it is closed, because a
list that only grows stops being read. What each closure actually decided lives where it is
useful rather than here:

- a rule that was **built** is in `core/internal/model/model.go`, with the measurement that
  justified it in the comment beside it
- a rule that was **measured and withdrawn** is in `core/internal/ledger/coverage.go`, with the
  numbers that killed it, in the shape CWE-1024's withdrawal takes
- what a fix actually did to real code is in the commit that made it
- what the engine can and cannot say is in the coverage ledger, which is the durable answer

### python-graphql-mutations-not-enumerated  MISS-SURFACE  seen in 1 repo
**What happened.** saleor enumerates **23 entry points against an independent reviewer's 428**,
and none of the 23 is GraphQL: they are 16 CLI commands, 5 HTTP routes and 2 process starts. The
repository contains **227 mutation classes** deriving from `BaseMutation`, `ModelMutation`,
`ModelDeleteMutation` and `DeprecatedModelMutation`.

GraphQL support was built in batch 1 and it was built for TypeScript: a NestJS `@Mutation()`
decorator. Python's Graphene registers a mutation by DERIVING A CLASS, which is a different
shape entirely, so the capability is declared in the model and enumerates nothing here.

This is the same failure as the ReDoS rule that existed and produced nothing, and the DRF router
that shipped without being exercised. **A capability tested only against the language it was
written for is a capability with one data point.**

**Where.** saleor@8c7815d83922 `saleor/graphql/**/mutations/*.py`

**What the engine should do.** In `frontends/python/src/lower.py`, a class deriving from a
Graphene mutation base is an entry point, and its surface is `perform_mutation` (and `mutate`),
whose arguments are the caller's. The class's `Arguments` inner class declares what the caller
may send, which is the same information a route's parameters carry. Queries derive from
`graphene.ObjectType` with resolver methods named `resolve_*`, and those are reachable too.

A mutation is reachable by anyone who can reach the schema, takes arguments the caller writes,
and runs its body. There is nothing about it that makes it less of a surface than a POST, which
is the argument that got the TypeScript half built.

**Fixture.** not yet extracted
**Status.** OPEN

### django-class-based-view-residual  MISS-SURFACE  seen in 1 repo
**What happened.** doccano enumerates 33 entry points after the keyword-registration fix took it
from 6, against an independent reviewer's 78. 62 of its 86 registrations are `SomeClass.as_view()`
and the shortfall is concentrated there.

**Where.** doccano@ab6b765ea326 `backend/*/urls.py`

**What the engine should do.** Unknown, deliberately. The keyword fix was measured; this residual
is not, and guessing at it mid-batch is how the last four wrong premises happened. The
adjudicator's run-quality section names what a surface is missing, and that is the input this
needs.

**Fixture.** not yet extracted
**Status.** OPEN, pending the adjudication

## Measurement

Batch 1, ten repositories, adjudicated three times: once against the engine as it was, once
after the first fix cycle, and once after the defect list closed. Same repositories, same
commits, same independent security reviews. Only the engine moved.

| | findings | true | false | disputed | missed | precision | recall | entry points |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| before any fixes | 161 | 45 | 92 | 15 | 67 | 33% | 40% | 345 |
| after the first cycle | 133 | 46 | 64 | 14 | 67 | 42% | 41% | 662 |
| after the list closed | **50** | **19** | **12** | 19 | 33 | **61%** | **37%** | **1714** |

**Precision 33% to 61%. The surface is five times larger. And recall is where it started.**

That last number is the honest one and it is worth sitting with. Sixty-eight defects closed,
and the share of the review's true findings the engine reproduces went 40% to 37%. The
denominator changed -- 67 misses became 33 -- so the engine is missing half as many things in
absolute terms while producing a third fewer findings. But it is not converging with the
second reader, and no amount of surface growth has made it converge.

The disputed rate rose from 9% to 38%, and eight of the nineteen are one question asked eight
times: whether `lxml`'s default parser resolves external entities in searxng's XML engines,
which cannot be established because the version is not in the tree. That is the template
reasoning the measurement tooling was built to flag, and it flagged it.

searxng alone is 30% of the batch's findings. That is exactly the concentration that moved the
headline fifteen points last time, which is why the per-repository share is now reported
beside the total rather than left to be discovered.

## Judgement calls I could not make

- **Taint through a dependency that is not in the tree** (uptime-kuma, 7 findings, 33% of that run). Assuming an unmodelled callee preserves taint is a defensible over-approximation. Whether `badge-maker.makeBadge` should produce seven HIGH findings, one finding, or none is a policy decision I can't make for you. The same question decides `server/setup-database.js`:267 (mysql2 exception text).
- **True weaknesses in vendored code.** uptime-kuma's single-DES ECB and MD4 NT hash are factually correct and live in a vendored NTLM implementation where they are protocol requirements. Should the engine report them, report them in a separate section, or not at all? The adjudicator marked them true-but-not-worth-reporting on a first-party criterion that came from the review prompt, not from the engine.
- **Documented opt-in dangerous settings.** uptime-kuma `server/notification-providers/teltonika.js`:51 sets `rejectUnauthorized: false` under an option literally named `teltonikaUnsafeTls` with a comment saying "Danger!". The engine is right about the code. Whether a deliberate, named, documented opt-in should be suppressed is a design question.
- **PBKDF2 at 10,000 iterations** (umami `src/lib/crypto.ts`:16). Neither side could decide: the callers pass a deployment secret whose entropy the repository never establishes. If the engine is expected to report work factors below a threshold regardless of input entropy, this is a true finding it got right; if not, it is noise. Pick one.
- **Reachability that depends on code outside the checkout.** unleash's ReDoS (`feature-naming-validation.ts`:3) has no in-tree setter for the pattern — the only one is enterprise code not in this repository. searxng's tracker-pattern regexes come from a hard-coded HTTPS feed. Should the engine assert on a dangerous sink whose only reachable writer is outside the analysed tree?
- **Hardening-class findings.** jupyterhub's non-constant-time XSRF comparison and umami's three reverse-tabnabbing calls to deployment-configured URLs are all "correct and not worth a person's attention". The `NOISE` kind exists for this, but the engine has no severity band that expresses it — everything is `level: error`, `confidence: high`. Whether these should be emitted below a gate or not at all is your call.
- **SSRF guard semantics from the standard library** (healthchecks `hc/lib/curl.py`:52). The guard reduces to `ipaddress.ip_address(ip).is_private`, and Python classifies `100.64.0.0/10` as neither private nor global — so shared-address-space targets pass. Modelling the negative space of a standard-library classifier is a real capability with real cost; I can't tell whether it belongs in the engine or in a hand-written rule pack.
- **Domain-specific semantics.** pdfjs's PDF signature ByteRange/Contents binding (`src/core/document.js`:2104) and jupyterhub's username-to-scope-filter substring collision (`jupyterhub/scopes.py`:781-784) are both real and both require understanding one file format or one permission grammar. These look to me like things a general engine should not attempt, but they were 2 of the 41 misses and someone should say so explicitly rather than leaving them uncounted.
- **One adjudicator claim I would not propagate without checking.** uptime-kuma `server/server.js`:1683 (cross-user monitor statistics) was called `unreachable` on the grounds that no second authenticated principal can exist — a negative claim over the whole application, made by a model that was simultaneously establishing that the engine had enumerated none of the 87 Socket.IO events. It cites `server.js`:711-714 for the setup refusal, which is real, but "there is no add-user route or event anywhere" is the kind of exhaustive negative that deserves a grep before it becomes a reason not to build the ownership rule. Two smaller ones: searxng `ahmia_filter.py`:43 is marked `true` while the reason concedes there is no practical second preimage — "true" is generous there; and uptime-kuma `setup-database.js`:267 is marked disputed on the thin basis that mysql2's exception text might contain nothing the caller did not already supply.

## python: `cls.method(...)` binds arguments one position off

Python declares `cls`/`self` as parameter zero and no call site writes it, so every argument
binds the parameter to its left. saleor's `cls._set_password_for_user(email, password, token)`
against `def _set_password_for_user(cls, email, password, token)` maps `password` to `email`.

Two independent agents hit this on the same day and neither could fix it in their lane:

- the Django-manager measurement named it as one of three defects found on the way;
- the caller-credential rule produced a FALSE SENTENCE because of it -- it cited
  `User.objects.get(email=email)` as "a record selected by the caller's password". The route
  really does authenticate by token, so the verdict was right and the citation was wrong,
  which is worse than silence. It now binds by NAME only and records the positional case as a
  stated miss.

That workaround is the cost: a secret handed down as a bare positional argument is invisible
to the credential rule, and every other analysis that reasons about argument position is
reading a shifted list on classmethod and instance-method calls.

**Why it is not just a recall bug.** An off-by-one binding does not go quiet, it says
something false about code somebody else wrote. We send these to maintainers.

Related: `f(x).attr` loses the call entirely (`lower.py`'s `attribute()` returns None when the
base is not an `ast.Name` and never visits it), and Django's `<int:pk>` never seeds a source
because `constrainedConverters` treats `int` as a sanitizer for every context -- right for
injection, wrong for record selection, and it is why Django's commonest detail route carries no
caller data into any ownership judgement.

## engine: byte-for-byte duplicate findings in the SARIF

25 of 342 findings across batch 3 are exact repeats of another result -- same rule, same file,
same line, same column. 21 are in ever-gauzy and 4 in defectdojo; the other eight
repositories have none.

**Why it is not cosmetic.** A duplicate inflates the finding count, inflates the precision
denominator if it is false, and doubles the adjudication cost of the finding. It also broke
the adjudication harness: defectdojo's slice 5 carried `metrics/views.py:676` twice, the
adjudicator wrote one row for it and said so in its report, and the slice floor threw the
whole slice away as incomplete. Twice, before anyone looked at why.

The floor now counts one row per (rule, file) rather than one per result, which is the right
shape independently: an adjudicator may legitimately answer two findings with one verdict
when they are the same defect, and defectdojo's `views.py:123` and `:124` are exactly that.
But the duplication itself is still a defect and should be deduplicated where findings are
reported, not tolerated by everything downstream.

Two repositories out of ten and 7% of findings, so it is not urgent. It is cheap.
