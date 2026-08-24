# Validation against real code

Fixture corpora prove the engine does what it was designed to do. They cannot tell you
whether what it was designed to do is right, because the same person wrote both.

This directory holds the other half: findings from unmodified real repositories, each one
adjudicated by hand or by an independent reviewer, recorded permanently.

## The asset is the verdict file, not the comparison

`verdicts.json` maps a finding's fingerprint to what it actually was. It accumulates. A
verdict recorded once is never re-adjudicated, so every future run is scored against
everything ever judged, and precision becomes a measured number that moves rather than an
impression.

The fingerprint is deliberately position-independent (ADR-014), so a verdict survives the
code being reformatted, an import being added above it, or the engine's line attribution
changing. It does NOT survive the finding genuinely changing shape - a different sink, a
different source, a different policy - which is correct: that is a different finding and
deserves its own judgement.

## Where the second opinion comes from

Anything independent: a reviewer reading the code, a different tool, an AI security review.
The harness does not care, and nothing about it ends up in the shipped binary. Using a
model to help decide what is true during development says nothing about whether the
product depends on one at runtime; this one does not.

What matters is that a disagreement is never resolved by preferring whoever is louder.
Each one is a case to investigate against the source, and the investigation is what gets
recorded.

## Verdicts

- `true` - a real defect. The engine was right.
- `false` - not a defect. The engine was wrong, and the reason says what it missed.
- `disputed` - defensible either way. A judgement a careful reviewer could go both ways on,
  recorded as such rather than forced into a bucket to make a number look better.
- `unreachable` - the flow cannot occur, usually because a guard the engine cannot see
  prevents it.

`disputed` is not a dumping ground. It exists because forcing genuinely ambiguous cases
into true or false is how precision numbers become fiction.
