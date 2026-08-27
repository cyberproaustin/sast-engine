#!/usr/bin/env python3
"""Score a corpus run against the adjudicated verdicts.

  python3 validation/score.py <corpus-dir>

Reports precision over the findings that have been judged, per CWE and overall, and says
how much of the run is still unjudged - because a precision figure computed over a tenth
of the output is not a precision figure.
"""
import json, pathlib, sys, collections

HERE = pathlib.Path(__file__).parent


def load_verdicts():
    p = HERE / "verdicts.json"
    if not p.exists():
        return {}
    verdicts = json.loads(p.read_text())["verdicts"]
    # A row re-keyed by rekey_fingerprints.py answers under both names, so a run scored
    # from artifacts an older build wrote is scored against the same judgement rather than
    # counted as unjudged.
    by_fingerprint = {v["supersedes"]: v for v in verdicts if v.get("supersedes")}
    by_fingerprint.update({v["fingerprint"]: v for v in verdicts})
    return by_fingerprint


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: score.py <corpus-dir>", file=sys.stderr)
        return 2
    corpus = pathlib.Path(sys.argv[1])
    verdicts = load_verdicts()

    by_cwe = collections.defaultdict(collections.Counter)
    unjudged = collections.Counter()
    total = 0

    for sarif in sorted((corpus / "out").glob("*.sarif")):
        doc = json.loads(sarif.read_text())
        for r in doc["runs"][0].get("results", []):
            if "expectationOrigin" in r["properties"]:
                continue  # advisory, not a finding
            fp = (r.get("partialFingerprints") or {}).get("sastEngine/v1")
            cwe = r.get("ruleId", "?")
            total += 1
            if fp and fp in verdicts:
                by_cwe[cwe][verdicts[fp]["verdict"]] += 1
            else:
                unjudged[cwe] += 1

    judged = sum(sum(c.values()) for c in by_cwe.values())
    print(f"{total} findings, {judged} judged, {total - judged} not yet judged\n")
    if not judged:
        print("nothing adjudicated yet; run adjudicate.py to produce review packets")
        return 0

    print(f"{'cwe':<10}{'true':>6}{'false':>7}{'disputed':>10}{'unreach':>9}{'precision':>11}")
    grand = collections.Counter()
    for cwe in sorted(by_cwe):
        c = by_cwe[cwe]
        grand.update(c)
        # Disputed findings count against precision. A tool cannot award itself the
        # benefit of the doubt on the cases a careful reader found genuinely unclear.
        decided = c["true"] + c["false"] + c["disputed"] + c["unreachable"]
        p = c["true"] / decided if decided else 0
        print(f"{cwe:<10}{c['true']:>6}{c['false']:>7}{c['disputed']:>10}{c['unreachable']:>9}{p:>10.2f}")

    decided = sum(grand.values())
    print(f"\n{'TOTAL':<10}{grand['true']:>6}{grand['false']:>7}{grand['disputed']:>10}"
          f"{grand['unreachable']:>9}{grand['true']/decided:>10.2f}")
    if unjudged:
        print(f"\nunjudged by cwe: {dict(unjudged)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
