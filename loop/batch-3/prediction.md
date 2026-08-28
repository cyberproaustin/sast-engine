# Batch 3 prediction, written before any repository was chosen

Recorded 2026-08-28, engine at 7846838 (196 corpora, all precision 1.00 recall 1.00).
Batch 2 finished at precision 80% (37 true / 46 decided) and recall 60% (37 of 62).

Those numbers are fitted by construction. Every fix this cycle came from the ten
repositories they are measured on. Batch 1 read 61% by the same method and then read 18% on
unseen code, so the only honest use of batch 3 is to find out which of those two numbers
batch 2 resembles.

## What I expect

**Precision 45 to 60 percent.** Lower than 80 and higher than batch 2's opening 18, because
several of this cycle's fixes were not rules at all: surface enumeration, workspace package
resolution, options-object parameters and the return-composition bug are facts about reading
programs rather than facts about these ten programs, and they should carry.

**Recall 30 to 40 percent.** Lower than 60 for the opposite reason. The rules that moved
recall hardest were framework-shaped: DRF declarative permissions, graphene Meta.permissions,
tRPC surfaces. A batch without those frameworks gets none of that benefit.

**Where the misses will cluster.** Resource exhaustion, races and cache-key completeness,
because those were measured and declined this cycle rather than solved. Plus one framework
idiom we have never modelled, which is the pattern every batch has produced so far.

## What would falsify what we think we know

- **Precision above 70.** The fixes generalise better than I believe and the fitting worry
  was overstated. Good news, and it means the holdout discipline can be relaxed.
- **Precision below 35.** Batch 2's 80 was almost entirely fitting, and the per-rule
  measurements that justified each fix were measuring the wrong thing.
- **Misses on shapes NOT in the batch-2 list.** Then `loop/issues.md` is a list of ten
  repositories' idioms rather than a list of engine gaps, and the fix order is wrong.
- **The same five confirmed-miss shapes recurring.** Then they are general, and they should
  be fixed before batch 4 rather than after.

## Rules for this batch

1. **The engine is frozen while batch 3 is measured.** No fixes land between the first scan
   and the last adjudication. Batch 2's first measurement had to be redone because four
   adjudications ran against artifacts I had already replaced.
2. **Three of the ten are sequestered.** Never read during fixing, scanned only at the end.
   This was designed after batch 2 and never built; the number it produces is the only one
   not fitted to the repositories that produced the fixes.
3. **This prediction is not edited after the fact.** If it is wrong it stays wrong on the page.
