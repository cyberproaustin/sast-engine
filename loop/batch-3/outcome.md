# Batch 3 outcome, against the prediction written before selection

**Precision 12% (25 true / 203 decided). Recall roughly 33% on the fix set.**

The prediction said 45 to 60 percent precision and 30 to 40 percent recall. Recall landed in
range. **Precision was wrong by a factor of four, and wrong in the direction the prediction
listed as falsifying: "Precision below 35. Batch 2's 80 was almost entirely fitting, and the
per-rule measurements that justified each fix were measuring the wrong thing."**

| | precision | recall |
|---|---|---|
| batch 2, as first measured | 18% | 19% |
| batch 2, after ~20 workstreams fixed against it | **80%** | 60% |
| batch 3, fresh code | **12%** | 33% |

Batch 2 opened at 18% and batch 3 opened at 12%. The 80% was the product of fitting to ten
repositories, and it did not survive contact with ten others.

## Fitted and unfitted agree, which is the cleanest part of the result

| | findings | true | false | disputed | precision |
|---|---|---|---|---|---|
| fix set (7) | 92 | 9 | 61 | 22 | **13%** |
| holdout (3) | 244 | 16 | 117 | 110 | **12%** |

The surface work was built against the fix set and the holdouts were never read. Route
coverage generalised -- misago went 58% to 101% untouched. Precision is identical across the
split because no RULE was fitted to batch 3 at all, so both numbers are the engine's true
out-of-the-box precision on code it has never seen.

## Two rules are 60% of the output and are never right

| rule | n | true | false | disputed | precision |
|---|---|---|---|---|---|
| CWE-284 | 120 | **0** | 77 | 43 | 0% |
| CWE-862 | 63 | 1 | 35 | 27 | 3% |
| everything else | 120 | 24 | 62 | 40 | **28%** |

CWE-284 is the population rule's fallback when it cannot classify the control it thinks is
missing: "something is absent here and I cannot say what." It fired 120 times across the
batch and was right zero times.

**117 of those 120 are in ONE repository.** ever-gauzy has 1542 entry points and a uniform
NestJS surface, so every route looks like every other route and the population infers a
missing control everywhere.

## The surface work made this worse, and that is worth stating plainly

Entry points feed the population rules. Every workstream this batch enlarged the surface --
netbox 128 to 2771, plane 51 to 592, oscar 30 to 192 -- and each of those enlargements gives
the expectation rules more peers to compare and more anomalies to report. The agents measured
"no expectation wave" on their own repositories and were right; the wave is on ever-gauzy,
which none of them was allowed to look at.

Excluding CWE-284, CWE-862 and CWE-306 entirely, precision is **28%**. That is the number the
rest of the engine earns without the population rules, and it is still not good.

## What this does not say

It does not say the engine is worse than it was. Batch 2's repositories still measure 80%,
and the four capabilities that produced that number -- the return-composition fix, workspace
resolution, options-object parameters, surface enumeration -- are facts about reading programs
and they carried. It says the RULES were tuned to ten applications and the tuning did not
transfer.

The honest headline for the tool remains what a maintainer can verify: seven reports sent from
batch 2, one rejected, and the engine found each of them itself.
