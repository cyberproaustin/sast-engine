#!/usr/bin/env python3
"""Produce review packets for findings that have not been judged yet.

  python3 validation/adjudicate.py <corpus-dir> [--cwe CWE-639] [--limit 20]

Each packet is one finding with its evidence path and the source around every hop, which
is what a reviewer needs to decide and no more. The output is meant to be read - by a
person, or handed to an independent reviewer - and the answer recorded in verdicts.json.

Findings already in verdicts.json are skipped. Judging is cumulative and a verdict is
never asked for twice.
"""
import argparse, json, pathlib, sys, collections

HERE = pathlib.Path(__file__).parent


def load_verdicts():
    p = HERE / "verdicts.json"
    return {v["fingerprint"] for v in json.loads(p.read_text())["verdicts"]} if p.exists() else set()


def source_at(root, uri, line, before=6, after=3):
    p = root / uri
    try:
        lines = p.read_text(errors="replace").splitlines()
    except Exception:
        return [f"      (source unavailable: {uri})"]
    out = []
    for i in range(max(0, line - before - 1), min(len(lines), line + after)):
        out.append(f"{i+1:>6}{'>' if i + 1 == line else ' '} {lines[i][:118]}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--cwe")
    ap.add_argument("--limit", type=int, default=25)
    args = ap.parse_args()

    corpus = pathlib.Path(args.corpus)
    judged = load_verdicts()
    roots = {}
    for line in (corpus / "repos.tsv").read_text().splitlines():
        if line.strip():
            name, lang, url, sub = line.split("\t")
            roots[name] = corpus / "repos" / name / sub

    shown = 0
    for sarif in sorted((corpus / "out").glob("*.sarif")):
        repo = sarif.stem
        for r in json.loads(sarif.read_text())["runs"][0].get("results", []):
            if "expectationOrigin" in r["properties"]:
                continue
            fp = (r.get("partialFingerprints") or {}).get("sastEngine/v1")
            if not fp or fp in judged:
                continue
            if args.cwe and r.get("ruleId") != args.cwe:
                continue
            if shown >= args.limit:
                print(f"\n(stopping at --limit {args.limit})")
                return 0
            shown += 1

            loc = r["locations"][0]["physicalLocation"]
            uri, line = loc["artifactLocation"]["uri"], loc["region"]["startLine"]
            print(f"\n{'='*100}")
            print(f"fingerprint {fp}   {r['ruleId']}   {repo}")
            print(f"entry:  {r['properties'].get('entryPoint','?')}")
            print(f"sink:   {r['properties'].get('sinkSymbol','?')} at {uri}:{line}")
            print(f"says:   {r['message']['text']}")
            root = roots.get(repo)
            if root:
                print("\n--- sink ---")
                print("\n".join(source_at(root, uri, line)))
                flows = r.get("codeFlows") or []
                if flows:
                    hops = flows[0]["threadFlows"][0]["locations"]
                    print(f"\n--- source, {len(hops)} hops back ---")
                    h = hops[0]["location"]["physicalLocation"]
                    print("\n".join(source_at(root, h["artifactLocation"]["uri"],
                                              h["region"]["startLine"], before=4, after=2)))
    if shown == 0:
        print("nothing left to judge for that filter")
    return 0


if __name__ == "__main__":
    sys.exit(main())
