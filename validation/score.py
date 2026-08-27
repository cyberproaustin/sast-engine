#!/usr/bin/env python3
"""Score a corpus run against the adjudicated verdict ledger.

  python3 validation/score.py <corpus-dir> [--compare-adjudication]

Reports micro and per-repository precision over findings the ledger has answered, plus the
macro-average across repositories. It also says how much of the run is genuinely new: a
precision figure computed over a tenth of the output is not a precision figure for the run.
"""
import argparse
import collections
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
LEDGER = HERE / "verdicts.json"
VERDICT_NAMES = ("true", "false", "disputed", "unreachable")


def load_verdicts(path=None):
    path = path or LEDGER
    if not path.exists():
        return {}
    verdicts = json.loads(path.read_text())["verdicts"]
    # A row re-keyed by rekey_fingerprints.py answers under both names, so a run scored
    # from artifacts an older build wrote is scored against the same judgement rather than
    # counted as unjudged.
    by_fingerprint = {v["supersedes"]: v for v in verdicts if v.get("supersedes")}
    by_fingerprint.update({v["fingerprint"]: v for v in verdicts})
    return by_fingerprint


def rows_of(path):
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    return document if isinstance(document, list) else (
        document.get("findings") or document.get("adjudication") or [])


def run_artifacts(corpus):
    """Accept the validation corpus layout, a loop workroot, or one loop run."""
    out = corpus / "out"
    if out.is_dir():
        return [(path.stem, path, None) for path in sorted(out.glob("*.sarif"))]

    children = []
    for directory in sorted(path for path in corpus.iterdir() if path.is_dir()):
        sarif = directory / "findings-engine.sarif"
        if sarif.exists():
            adjudication = directory / "adjudication.json"
            children.append((directory.name, sarif,
                             adjudication if adjudication.exists() else None))
    if children:
        return children

    sarif = corpus / "findings-engine.sarif"
    if sarif.exists():
        adjudication = corpus / "adjudication.json"
        return [(corpus.name, sarif, adjudication if adjudication.exists() else None)]
    return []


def decided(counter):
    return sum(counter[name] for name in VERDICT_NAMES)


def precision(counter):
    count = decided(counter)
    return counter["true"] / count if count else None


def repeated_reasons(rows, engine_only=False):
    grouped = collections.defaultdict(list)
    for row in rows:
        if engine_only and row.get("found_by") not in ("engine", "both"):
            continue
        reason = (row.get("reason") or "").strip()
        if reason:
            grouped[reason].append(row)
    return [(reason, matches) for reason, matches in grouped.items() if len(matches) > 1]


def print_table(title, by_repo, unjudged_by_repo):
    print(title)
    print(f"{'repository':<16}{'true':>6}{'false':>7}{'disputed':>10}{'unreach':>9}"
          f"{'answered':>10}{'new':>7}{'share':>8}{'precision':>11}")
    grand = collections.Counter()
    answered = sum(decided(counter) for counter in by_repo.values())
    repository_precisions = []
    for repo in sorted(set(by_repo) | set(unjudged_by_repo)):
        counter = by_repo[repo]
        count = decided(counter)
        grand.update(counter)
        repo_precision = precision(counter)
        if repo_precision is not None:
            repository_precisions.append(repo_precision)
        share = count / answered if answered else 0
        precision_text = f"{repo_precision:.2f}" if repo_precision is not None else "-"
        print(f"{repo:<16}{counter['true']:>6}{counter['false']:>7}"
              f"{counter['disputed']:>10}{counter['unreachable']:>9}{count:>10}"
              f"{unjudged_by_repo[repo]:>7}{share:>7.0%}{precision_text:>11}")

    micro = precision(grand)
    macro = (sum(repository_precisions) / len(repository_precisions)
             if repository_precisions else None)
    print(f"\nMICRO precision over judged findings: {micro:.2f} "
          f"({grand['true']}/{decided(grand)})")
    print(f"MACRO precision across {len(repository_precisions)} repositories: {macro:.2f}")
    return grand, micro, macro


def print_template_reasons(groups):
    if not groups:
        return
    print("\nTEMPLATE REASON WARNINGS")
    for repo, reason, rows in sorted(groups, key=lambda item: (-len(item[2]), item[0], item[1])):
        preview = " ".join(reason.split())
        if len(preview) > 140:
            preview = preview[:137] + "..."
        print(f"{repo}: {len(rows)} verdicts share one reason; treat as N=1 data point")
        print(f"  {preview}")


def comparison_counts(artifacts):
    by_repo = collections.defaultdict(collections.Counter)
    groups = []
    for repo, _, adjudication in artifacts:
        if not adjudication:
            continue
        rows = rows_of(adjudication)
        engine_rows = [row for row in rows if row.get("found_by") in ("engine", "both")]
        by_repo[repo].update(row.get("verdict") for row in engine_rows)
        groups.extend((repo, reason, matches)
                      for reason, matches in repeated_reasons(engine_rows))
    return by_repo, groups


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=pathlib.Path)
    parser.add_argument("--compare-adjudication", action="store_true",
                        help="show the run's non-authoritative adjudication beside ledger scoring")
    args = parser.parse_args(argv)

    artifacts = run_artifacts(args.corpus)
    if not artifacts:
        print(f"no SARIF runs found under {args.corpus}", file=sys.stderr)
        return 1
    verdicts = load_verdicts()

    by_cwe = collections.defaultdict(collections.Counter)
    by_repo = collections.defaultdict(collections.Counter)
    unjudged_by_cwe = collections.Counter()
    unjudged_by_repo = collections.Counter()
    used_verdicts = {}
    total = 0

    for repo, sarif, _ in artifacts:
        document = json.loads(sarif.read_text())
        for result in document["runs"][0].get("results", []):
            if "expectationOrigin" in result.get("properties", {}):
                continue  # advisory, not a finding
            fingerprint = (result.get("partialFingerprints") or {}).get("sastEngine/v1")
            cwe = result.get("ruleId", "?")
            total += 1
            if fingerprint and fingerprint in verdicts:
                recorded = verdicts[fingerprint]
                by_cwe[cwe][recorded["verdict"]] += 1
                by_repo[repo][recorded["verdict"]] += 1
                used_verdicts[recorded["fingerprint"]] = recorded
            else:
                unjudged_by_cwe[cwe] += 1
                unjudged_by_repo[repo] += 1

    answered = sum(decided(counter) for counter in by_repo.values())
    print(f"{total} findings: {answered} already answered by the verdict ledger; "
          f"{total - answered} genuinely new/unjudged\n")
    if answered:
        print_table("AUTHORITATIVE LEDGER SCORE", by_repo, unjudged_by_repo)

        print(f"\n{'cwe':<10}{'true':>6}{'false':>7}{'disputed':>10}{'unreach':>9}"
              f"{'answered':>10}{'new':>7}{'precision':>11}")
        for cwe in sorted(set(by_cwe) | set(unjudged_by_cwe)):
            counter = by_cwe[cwe]
            cwe_precision = precision(counter)
            precision_text = f"{cwe_precision:.2f}" if cwe_precision is not None else "-"
            print(f"{cwe:<10}{counter['true']:>6}{counter['false']:>7}"
                  f"{counter['disputed']:>10}{counter['unreachable']:>9}{decided(counter):>10}"
                  f"{unjudged_by_cwe[cwe]:>7}{precision_text:>11}")
    else:
        print("nothing adjudicated yet; run adjudicate.py to produce review packets")

    ledger_groups = [("ledger", reason, matches)
                     for reason, matches in repeated_reasons(used_verdicts.values())]
    _, adjudication_groups = comparison_counts(artifacts)
    print_template_reasons(ledger_groups + adjudication_groups)

    if args.compare_adjudication:
        comparison, _ = comparison_counts(artifacts)
        if comparison:
            # This exists to reproduce historical figures. It must never feed the
            # authoritative score: the same run is exactly where verdicts proved unstable.
            print("\nRECORDED RUN ADJUDICATION (comparison only; not authoritative)")
            print(f"{'repository':<16}{'true':>6}{'false':>7}{'disputed':>10}"
                  f"{'unreach':>9}{'rows':>7}{'precision':>11}")
            grand = collections.Counter()
            precisions = []
            for repo in sorted(comparison):
                counter = comparison[repo]
                grand.update(counter)
                repo_precision = precision(counter)
                if repo_precision is not None:
                    precisions.append(repo_precision)
                print(f"{repo:<16}{counter['true']:>6}{counter['false']:>7}"
                      f"{counter['disputed']:>10}{counter['unreachable']:>9}"
                      f"{decided(counter):>7}{repo_precision:>10.2f}")
            print(f"\nOLD MICRO precision: {grand['true']/decided(grand):.2f} "
                  f"({grand['true']}/{decided(grand)})")
            print(f"OLD MACRO precision across {len(precisions)} repositories: "
                  f"{sum(precisions)/len(precisions):.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
