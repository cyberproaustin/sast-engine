#!/usr/bin/env python3
"""Fold loop adjudications into the permanent verdict ledger.

  python3 validation/ingest_loop.py <workroot>

A verdict recorded once is never asked for again. That is the whole point of the ledger, and
it is the answer to the thing that made batch 1's precision figure untrustworthy: eighteen
yt-dlp findings were adjudicated true in one pass and false in the next, on identical code at
an identical commit, and that one repository moved the headline by fifteen points.

An adjudicator is a reader, not an oracle. Its verdict is worth recording precisely because
recording it stops us asking a second time and getting a different answer.

Matched by FINGERPRINT, which the SARIF already carries and which is position-independent
(ADR-014), so a verdict survives the file being reformatted. The adjudication speaks in
file:line, so the join happens here rather than being asked of the adjudicator.
"""
import json, pathlib, sys, collections

HERE = pathlib.Path(__file__).parent
LEDGER = HERE / "verdicts.json"


def rows_of(p):
    try:
        d = json.loads(p.read_text())
    except Exception:
        return []
    return d if isinstance(d, list) else d.get("findings") or d.get("adjudication") or []


def main(work):
    doc = json.loads(LEDGER.read_text())
    # `supersedes` is the key a row USED to have, before a fingerprint change split
    # colliding siblings apart (see rekey_fingerprints.py). Artifacts written by the
    # previous build still name it, and a verdict recorded once is never asked for again --
    # so the old key answers for the row exactly as the new one does.
    known = {v["fingerprint"] for v in doc["verdicts"]}
    known |= {v["supersedes"] for v in doc["verdicts"] if v.get("supersedes")}
    added, skipped, unmatched = [], 0, 0

    for d in sorted(pathlib.Path(work).iterdir()):
        sarif, adj = d / "findings-engine.sarif", d / "adjudication.json"
        if not (sarif.exists() and adj.exists()):
            continue
        # file:line -> fingerprint, for the engine's own findings only. A review-only row
        # has no fingerprint because the engine never produced it, and a verdict about a
        # finding we did not make is not a verdict about us.
        index = {}
        for r in json.loads(sarif.read_text())["runs"][0].get("results", []):
            loc = r["locations"][0]["physicalLocation"]
            index[(loc["artifactLocation"]["uri"], loc["region"]["startLine"])] = (
                r["partialFingerprints"]["sastEngine/v1"], r["ruleId"])

        for row in rows_of(adj):
            if row.get("found_by") not in ("engine", "both"):
                continue
            hit = index.get((row.get("file"), row.get("line")))
            if not hit:
                unmatched += 1
                continue
            fp, cwe = hit
            if fp in known:
                skipped += 1
                continue
            known.add(fp)
            added.append({
                "fingerprint": fp,
                "cwe": cwe,
                "verdict": row.get("verdict"),
                "reason": (row.get("reason") or "").strip(),
                "adjudication": "read",
                "by": "codex+claude",
                "repo": d.name,
                "date": "2026-08-26",
            })

    doc["verdicts"].extend(added)
    LEDGER.write_text(json.dumps(doc, indent=2) + "\n")
    tally = collections.Counter(v["verdict"] for v in added)
    print(f"added {len(added)}  already recorded {skipped}  no engine finding at that line {unmatched}")
    print(f"new verdicts: {dict(tally)}")
    print(f"ledger now holds {len(doc['verdicts'])}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
