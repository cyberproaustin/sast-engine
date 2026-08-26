# The review loop

Fixture corpora prove the engine does what it was designed to do. The 28-repository clean
corpus proves it stays quiet on code that is fine. Neither can tell us what the engine
does not know how to say, because the same person wrote the engine and chose the corpus.

The loop is the instrument for that. One hundred unmodified public repositories, none of
them ours, none of them chosen by popularity, each one read three times by parties that do
not share a failure mode, with every disagreement investigated against the source and the
answer written down permanently.

The output of the loop is not a score. It is `loop-issues.md`, the list of things the
engine cannot yet say, and the fixtures extracted from real code that prove each one.

---

## Why three parties

Our engine is deterministic and has no model in it. A security review by a model reads
code the way a person does and finds things no rule was written for. These two disagree in
both directions, and neither is ground truth.

A third reviewer that has seen both, and must cite the source line for every verdict, is
what turns a disagreement into a decision. Codex fills that seat because it is a different
model family with a different training run, so it does not inherit the review's specific
mistakes.

Two cautions are worth stating plainly, because the design depends on them being handled
rather than hoped away:

**Two models can be wrong the same way.** Both will trust a function called `sanitize()`
without reading it. Both will assume a framework escapes by default. The countermeasure is
that codex must quote the line it is judging, that our deterministic track does not share
those instincts at all, and that a claim only survives if it is grounded in something one
of the three can point at.

**An LLM adjudicating an LLM is not full independence.** So the adjudication is not the
last word. It is a ranked, evidence-carrying packet, and the last word is mine.

---

## The unit of work: one repository

### Stage 0. Eligibility, decided before anything is cloned

Every candidate is checked against the GitHub API before it is fetched, and the answers are
written into the manifest. This is the authorization record, and it exists whether or not
we ever contact anyone.

Admitted licenses, by SPDX identifier: `MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`,
`ISC`, `MPL-2.0`, `GPL-2.0`, `GPL-3.0`, `AGPL-3.0`, `LGPL-2.1`, `LGPL-3.0`, `EPL-2.0`,
`Unlicense`, `0BSD`, `CC0-1.0`.

Refused without argument:

- **No `LICENSE` file at all.** Public does not mean licensed. Absent a grant, the code is
  all rights reserved, and that is the single most common way a repository looks open and
  is not.
- `NOASSERTION`, or a licence GitHub cannot identify.
- Source-available terms: BUSL, SSPL, Elastic License, Confluent, anything carrying the
  Commons Clause, anything with a field-of-use restriction.
- Archived repositories, forks, mirrors, and anything under 2000 lines.

Also recorded at this stage, deliberately before we know whether there is anything to
report: whether `SECURITY.md` exists and what it says, and whether GitHub private
vulnerability reporting is enabled. Choosing the disclosure channel before seeing the
finding is what keeps the choice honest.

What we are doing is reading published source code and running a static analyser over it
on our own hardware. No request is ever sent to anything the project operates. The licences
above all grant the right to use and study the code, so the activity is authorized on its
face. The record exists so that the authorization can be shown, not assumed.

### Stage 1. Clone and pin

`git clone --depth 1`, then record the exact commit SHA. Every finding, every verdict and
every report cites that SHA. A maintainer who receives a report can check out the same
commit and see the same lines.

### Stage 2. Dual track, in parallel, mutually blind

**Track A, the engine.** Lower with the TypeScript or Python frontend, scan with `sast`,
emit SARIF and text. Deterministic. Also captured: entry-point count, lowering wall time,
any crash or timeout, and any directory the frontend skipped.

**Track B, the security review.** A subagent reads the repository as a reviewer would and
reports findings in the same shape: file, line, CWE, confidence, the reasoning, and the
evidence it relied on.

Track B never sees Track A's output. This is not a detail. A reviewer shown a tool's
findings first will anchor on them, confirm most of them, and stop looking. The value of
the second read is entirely in it being an independent read.

### Stage 3. Codex adjudicates

Codex runs read-only against the pinned tree, holding both finding sets, and produces two
artifacts.

`adjudication.json`, one row per finding:

| field | meaning |
|---|---|
| `fingerprint` | position-independent, matches the existing ledger |
| `found_by` | `engine`, `review`, or `both` |
| `verdict` | `true`, `false`, `disputed`, `unreachable` |
| `evidence` | the source line codex is judging, quoted, with its path and line |
| `reason` | one or two sentences, grounded in that line |
| `reachable_from` | the entry point it is reachable from, or `none` |

`codex-report.md`, prose, covering four things:

1. **The clashes.** Every finding one track produced and the other did not, with a judgement
   on which was right and why. This is the most valuable section in the whole loop, because
   it is where the engine's blind spots are named by someone who is not us.
2. **False positives**, with what specifically the engine failed to see. Not "this is a false
   positive" but "the value is validated by `assertSafePath` at `lib/fs.ts:41`, which the
   engine did not follow because it returns through a type predicate".
3. **Run quality.** Did the frontend crash, time out, skip a directory that mattered, or
   enumerate a route count that does not match reality. A run that scanned a third of the
   repository produces findings that mean nothing, and that has to be caught here.
4. **What neither track looked at.** The parts of the attack surface that went unexamined.

Codex is told to judge against the source and not against provenance. Which tool found
something is context, never evidence.

### Stage 4. My review, and its exact scope

I read four things and nothing else:

1. The counts table and the clash list.
2. **Every row where the three parties are not unanimous.** Unanimous agreement is taken.
3. **Every row proposed for maintainer contact, verified by me at the source line, without
   exception.** A human being is going to read that report. Nobody's time gets taken on a
   claim I have not personally checked.
4. The run-quality section, in full, every time.

I do not read the full finding lists, the full source, or the rows all three agree on. If a
batch would exceed the budget, the batch summary is written to a file and I read the file.

Budget: about sixty lines of my context per repository, six hundred per batch of ten. That
number is the constraint the whole design is built around, and it is why codex writes the
report rather than me reading the findings.

### Stage 5. Record, before anything is deleted

**The verdict ledger.** Findings append to `validation/verdicts.json`, which already exists,
already holds 61 hand-adjudicated verdicts, and is already fingerprint-keyed and
append-only. Loop verdicts carry `"by": "codex+claude"` so a later reader can tell how each
one was reached. A verdict recorded once is never asked for again, which is what makes
precision a number that moves rather than an impression.

**`loop-issues.md`.** Every tool defect, deduplicated by fingerprint, with a recurrence
count. One entry per distinct defect, not per repository, because six repositories hitting
the same gap is one fix and the count is what tells us it is urgent.

Each entry carries a kind:

- `MISS-RULE` a real weakness with no rule for it
- `MISS-SYMBOL` the rule exists, the symbol is not in the model
- `MISS-SURFACE` the entry point was never enumerated, so nothing downstream was reachable
- `MISS-FLOW` source and sink both known, the path did not connect
- `FALSE-BROAD` the rule states something too loosely
- `FALSE-SANITIZER` a real guard the engine does not recognise
- `SURFACE-OVER` routes reported that are not routes
- `CRASH` frontend or core failed on real code
- `NOISE` correct, and still not worth a person's attention

**Fixtures, extracted before deletion.** Every confirmed `MISS` and every confirmed `FALSE`
becomes a minimized fixture in `testdata/` with an `expected.json`, reduced to the smallest
code that still reproduces it. This is the step that makes the loop compound instead of
repeat. A gap found in repository 7 and fixed in the batch-1 fix cycle is a regression test
forever after. A gap found and not extracted is a gap we will find again at repository 60.

### Stage 6. Delete the tree, keep the record

The working tree is deleted, as intended: a hundred cloned applications is not something to
keep on disk, and holding them creates a temptation to tune against them.

What is kept is small and text: the URL, the pinned SHA, the SPDX identifier, both finding
sets, the adjudication, codex's report, and any fixture. Roughly a megabyte per repository.

I am amending the instruction on one point and want to be explicit about it. You said
delete the repository and repeat, and the tree does get deleted. But if the artifacts go
too, then nothing is reproducible: a fix made in the batch-1 cycle cannot be checked against
the thing it was supposed to fix, and a maintainer who replies four weeks later asks about a
finding we no longer hold. Keeping the paper record and pinning the SHA means any repository
can be restored exactly by re-cloning, and costs almost nothing.

---

## Reporting to maintainers

### The bar

A report is sent only when all five hold:

1. I verified it myself, at the source, at the pinned commit.
2. It is reachable from an entry point the engine enumerated. A weakness in code nothing
   reaches is not a vulnerability.
3. It is in first-party code, not a vendored dependency or a test fixture.
4. It is not already known. Open issues and published advisories are searched first.
5. All three parties agree, or my own reading resolves the disagreement toward real.

`disputed` is a legitimate outcome and is never forced into `true` to have something to
send. No bulk submissions and no more than one report per repository per batch.

### The channel, in order

1. Whatever `SECURITY.md` instructs, followed exactly, including any embargo it asks for.
2. GitHub private vulnerability reporting, where the repository has it enabled.
3. A public issue, but only where the finding is not exploitable against a deployed instance.
4. Where there is no private channel and the finding is sensitive: a short public issue
   asking for a private channel, containing no details.

### What the report says

Written by a subagent to the template below, then read by me line by line before it is sent.
Nothing goes out that I have not read.

Required, non negotiable:

- **No em dashes.** Not anywhere in the report.
- Concrete impact. What an attacker can actually do, in one sentence, in the maintainer's
  terms. Not a CWE title and not a severity word.
- The exact path, file, line, and commit SHA, and the route or entry point it is reachable
  from.
- A plain statement that this came from static analysis of the source, that we did not run
  the application, and that runtime context we cannot see may make the finding wrong.
- That we were testing a static analysis tool, and that the maintainer is under no obligation
  to spend time on it.
- Questions to cyberproaustin@gmail.com.

Forbidden: severity scores we invented, "critical" as an adjective, urgency language,
anything that reads as generated, a wall of boilerplate, and any suggestion that a response
is owed.

### Template

```
Title: <specific behaviour>, <path> (<verb> <route>)

Hello,

I was testing a static application security testing tool against public repositories and
it flagged something in <repo> that I think is real. I read it myself before writing this,
and I am sending it because it looked worth your time rather than because a tool produced it.

Commit: <sha>
File: <path>:<line>
Reachable from: <verb> <route>, defined at <path>:<line>

What happens

<Two to four sentences. The path the value takes, in the code's own terms.>

Impact

<One or two sentences. What someone can do with it.>

A caveat that matters

This came from static analysis. I read the source at the commit above, I did not run the
application, and I have no access to your deployment. If there is a check somewhere the
analysis could not follow, or a reason this path is unreachable in practice, then this is
wrong and I would genuinely like to know, because that is a gap in the tool.

I am not asking for a response and there is no obligation here. If you have questions or
want anything clarified, cyberproaustin@gmail.com.
```

Every report is logged in `loop/reports/` with its channel, date, and any reply. A
maintainer telling us we are wrong is one of the most valuable results available, and it
goes into `loop-issues.md` as a `FALSE` entry.

---

## Choosing the hundred

Star count is not used, at any stage, for anything.

It selects for libraries, and a library has no attack surface. The 1475-route
over-enumeration and the 8353-entry-point correction both came from applications with real
routing, and popularity does not predict that.

Required of a candidate:

- It is an **application or service**: it has routes, or it is a CLI that consumes untrusted
  input, or it parses a format somebody else produces.
- TypeScript, JavaScript, or Python, since that is what we can lower.
- An admitted licence, per Stage 0.
- Not in the 28-repository clean corpus or the 7 vulnerable applications. Those are the
  measurement baseline and scanning them here would poison it.

How they are found, none of it ordered by popularity:

- Curated lists of self-hosted applications, Django and Flask application indexes, and
  similar catalogues that select for "is a working application".
- GitHub code search by framework import, sampled across creation-year buckets, so 2015 code
  and 2025 code are both represented.
- Package registry entries whose linked repository is an application rather than a library.
- A deliberate tail: obscure projects with few watchers and real routes. Code nobody has
  audited is where an unaudited tool learns the most.

Target shape, adjusted as we learn:

| axis | target |
|---|---|
| TypeScript / JavaScript | 60 |
| Python | 40 |
| Express or Koa | at least 12 |
| NestJS | at least 8 |
| Next.js or Remix file routes | at least 8 |
| Fastify or Hapi | at least 6 |
| Flask | at least 10 |
| Django or DRF | at least 12 |
| FastAPI | at least 8 |
| aiohttp, Tornado, Bottle, Sanic | at least 6 |
| non-web, CLI or parser | at least 8 |

Domains spread deliberately across content management, commerce, chat, CI, monitoring,
wikis, ERP, file sync, dashboards, and developer tooling. Sizes spread from a few thousand
lines to monorepos.

Selection happens one batch at a time, not all hundred up front, so the choice can respond
to what the previous batch taught us. If batch 2 shows the engine is blind to a framework,
batch 3 gets more of it.

---

## Batches, and the fix cycle

Ten repositories, then stop and fix. Ten more. Ten times.

### The completion rule

**A batch is not finished when the ten repositories have been read. It is finished when
every defect they exposed has been closed.** Reading is the cheap half. The loop exists to
make the engine better, and a defect that is recorded and not fixed has cost us the reading
and bought nothing.

A defect may be closed exactly two ways:

1. **Fixed**, with a fixture extracted from the real code that exposed it, failing before and
   passing after.
2. **Measured and withdrawn**, with the numbers written down. Not "this looks hard to
   integrate", not "this needs a new strategy", not "this would probably be noisy" -- an
   actual count, on the clean corpus, showing the fix costs more than it buys. CWE-1024 is
   the example to follow: it was built, measured, found to fire only on a spelling the
   engine deliberately does not treat as text, and withdrawn with that reason recorded.

**"Open pending measurement" is not a terminal state.** It is a task. If the fix needs a
measurement first, the measurement is part of the work, not an alternative to it. Deferring
on an unmeasured guess is how thirty-one defects sat open after the first batch while six got
fixed, and that is the failure this rule exists to prevent.

Difficulty is not a reason to decline. A weakness the engine cannot currently state is
precisely the interesting case: it means either a rule is missing, a seeding strategy is
missing, or the IR does not carry a fact it needs. All three are buildable, and all three are
the point.

### What we are converging on

The two readers should agree. When an independent security review finds something and the
engine does not, that gap is the work; when the engine finds something the review would not
have, that is the engine earning its place. Convergence in both directions is the target, and
the numbers to watch across batches are:

- **the share of the review's true findings the engine also produced** -- 25% after batch 1
- **precision on what the engine reports** -- 20% after batch 1
- **enumerated surface against registrations counted in source** -- 39% after batch 1

None of those is acceptable and all three are measurable, which is the only reason to state
them.

### The cost curve is deliberate

**Batch 1 should be the most expensive thing this project ever does, and it was not expensive
enough.** The first ten repositories exposed three entire framework conventions the engine
could not see and a source-seeding gap that made an exactly-enumerated surface completely
inert. Closing all of that is a large amount of work, and doing it now is what makes batch 2
cheaper.

Expect the curve: batch 1 the longest by far, batch 2 meaningfully less, and by the last ten
repositories a batch should surface little the engine has not already learned. If batch 40 is
still producing framework-shaped surprises, the loop is not compounding and something about
the selection or the fixing is wrong.

### During a batch

Repositories run as a rolling pipeline, three in flight. Lowering holds an exclusive lock
because a monorepo frontend run needs up to ten gigabytes and the machine has thirty one, so
only one lowers at a time while the others are in review, adjudication, or recording. The
model stages are where the wall time is, and this hides most of it. Nothing is fixed
mid-batch: a change to the engine partway through would mean the ten repositories were
scanned by two different engines, and the batch would measure nothing.

### At the boundary

1. Read `loop-issues.md`, grouped by recurrence count. Six repositories hitting one gap
   outranks one repository hitting six. Recurrence sets the ORDER, never the cut: everything
   gets done.
2. Fix in that order. Every fix lands with the fixture extracted from the real code that
   exposed it.
3. **The regression gate.** All four must hold:
   - every fixture corpus still at precision 1.00
   - the clean corpus gating count does not increase
   - the vulnerable corpus gating count does not decrease
   - `go build ./...`, `go test ./...`, and `gofmt -l .` all clean
4. **Re-run the batch's repositories against the fixed engine, and re-adjudicate anything
   whose findings or surface moved.** A fix is not verified by the fixture alone. The
   repository that exposed the defect is the test that matters, and a surface that grew by a
   hundred entry points is a different program to judge.
5. Re-measure both corpora, update the coverage ledger and the README.
6. Commit and push.
7. **Confirm every defect from the batch is closed.** If any remains open, the batch is not
   finished and the next ten do not start.
8. Report: what was found, what was fixed, what was measured and withdrawn with its numbers,
   which reports went to maintainers and what came back.

## What the loop cannot do

It will not tell us the engine is finished, and it will not produce a recall number worth
quoting. A hundred repositories judged by two models and one deterministic tool is a sample,
and the things all three miss are invisible to it by construction.

What it does produce is a list of specific things the engine could not say, each one grounded
in code somebody actually shipped, each one carrying a fixture. That list is worth more than
a percentage, and it is the only artifact here that compounds.

---

## Where everything lives

```
loop-issues.md              the defect list, deduplicated, recurrence-counted
loop/manifest.tsv           the hundred: url, sha, spdx, language, framework, batch, status
loop/runs/<repo>/           findings-engine.sarif, findings-review.json,
                            adjudication.json, codex-report.md, meta.json
loop/reports/               maintainer reports, channel, date, reply
validation/verdicts.json    the permanent verdict ledger (existing, append-only)
testdata/<fixture>/         minimized reproductions extracted before deletion
```
