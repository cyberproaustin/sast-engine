#!/usr/bin/env python3
"""Turn MITRE's published CWE catalog into the ledger the engine reports against.

Run:  python3 catalog/generate.py

Everything here is DERIVED. No CWE identifier, name, or relationship is ever typed by a
human into this project: an earlier batch of taxonomy identifiers was written from memory
and every one of the eight was wrong, and at the scale of a thousand entries that failure
mode would quietly poison the whole coverage map.

What the engine claims about each weakness lives separately, in coverage.go, keyed by id.
Regenerating this file therefore cannot lose our work, and adopting a new CWE release is a
re-run rather than a merge.
"""
import json, pathlib, sys, xml.etree.ElementTree as ET

NS = {"c": "http://cwe.mitre.org/cwe-7"}
HERE = pathlib.Path(__file__).parent

# Languages this engine has, or could plausibly have, a frontend for. Used only to mark an
# entry out of scope; it is never used to hide one.
OURS = {"JavaScript", "Python", "PHP", "Java", "Ruby", "Go", "TypeScript"}


def main() -> int:
    src = sorted(HERE.glob("cwec_v*.xml"))
    if not src:
        print("no cwec_v*.xml in catalog/; download it from cwe.mitre.org", file=sys.stderr)
        return 2
    catalog = src[-1]
    root = ET.parse(catalog).getroot()

    entries = []
    for w in root.findall(".//c:Weakness", NS):
        langs = set()
        for lang in w.findall(".//c:Applicable_Platforms/c:Language", NS):
            langs.add(lang.get("Name") or lang.get("Class") or "")

        methods = [m.findtext("c:Method", default="", namespaces=NS)
                   for m in w.findall(".//c:Detection_Method", NS)]

        entries.append({
            "id": "CWE-" + w.get("ID"),
            "name": w.get("Name"),
            # Pillar and Class are abstractions over other entries; Base and Variant are
            # the ones with a code shape a rule can be written against.
            "abstraction": w.get("Abstraction"),
            "status": w.get("Status"),
            # MITRE's own judgement about whether a tool can find this, which is a better
            # source than mine.
            "staticDetectable": any("Static Analysis" in m for m in methods),
            "languages": sorted(x for x in langs if x),
            "languageAgnostic": (not langs) or ("Not Language-Specific" in langs),
        })

    entries.sort(key=lambda e: int(e["id"].split("-")[1]))
    out = {
        "source": catalog.name,
        "version": root.get("Version"),
        "date": root.get("Date"),
        "weaknesses": entries,
    }
    # Written straight into the package that embeds it: one copy, so the build and the
    # generator can never disagree about which release is in force.
    dest = HERE.parent / "core" / "internal" / "ledger" / "cwe.json"
    dest.write_text(json.dumps(out, indent=1) + "\n")

    scoped = [e for e in entries
              if e["status"] != "Deprecated" and e["staticDetectable"]
              and (e["languageAgnostic"] or (set(e["languages"]) & OURS))]
    shapes = [e for e in scoped if e["abstraction"] in ("Base", "Variant")]
    print(f"{dest}: CWE {out['version']} ({out['date']})")
    print(f"  {len(entries)} weaknesses")
    print(f"  {len(scoped)} in scope (static-detectable, not deprecated, our languages)")
    print(f"  {len(shapes)} of those are Base or Variant, i.e. have a code shape")
    return 0


if __name__ == "__main__":
    sys.exit(main())
