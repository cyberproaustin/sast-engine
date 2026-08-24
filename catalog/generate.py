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

    # The catalog carries its own priority lists as views, so which weaknesses matter most
    # is read from MITRE rather than decided here. Membership is recorded per entry, and
    # the report uses it to say how much of each list the engine covers.
    PRIORITY_VIEWS = {
        "1435": "cwe-top-25-2025",
        "1450": "owasp-top-ten-2025",
    }
    # The OWASP Top Ten is published in the catalog as ten CATEGORIES, each listing the
    # weaknesses that roll into it. Reading it here retires the last taxonomy mapping in
    # this project that a human wrote from memory -- the previous one was wrong in eight
    # places out of eight.
    owasp: dict[str, str] = {}
    categories = {c.get("ID"): c for c in root.findall(".//c:Category", NS)}
    owasp_view = next((v for v in root.findall(".//c:View", NS) if v.get("ID") == "1450"), None)
    if owasp_view is not None:
        for member in owasp_view.findall(".//c:Has_Member", NS):
            cat = categories.get(member.get("CWE_ID"))
            if cat is None:
                continue
            # "OWASP Top Ten 2025 Category A01:2025 - Broken Access Control"
            label = (cat.get("Name") or "").split("Category", 1)[-1].strip()
            for w in cat.findall(".//c:Has_Member", NS):
                owasp.setdefault("CWE-" + w.get("CWE_ID"), label)

    memberships: dict[str, list[str]] = {}
    for view in root.findall(".//c:View", NS):
        label = PRIORITY_VIEWS.get(view.get("ID"))
        if not label:
            continue
        for member in view.findall(".//c:Has_Member", NS):
            memberships.setdefault("CWE-" + member.get("CWE_ID"), []).append(label)

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
            "lists": sorted(memberships.get("CWE-" + w.get("ID"), [])),
            "owasp": owasp.get("CWE-" + w.get("ID"), ""),
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
    print(f"  {sum(1 for e in entries if e['owasp'])} weaknesses carry an OWASP Top Ten 2025 category")
    for label in sorted(set(l for e in entries for l in e["lists"])):
        n = sum(1 for e in entries if label in e["lists"])
        ours = sum(1 for e in scoped if label in e["lists"])
        print(f"  {label}: {n} members, {ours} in scope for this engine")
    return 0


if __name__ == "__main__":
    sys.exit(main())
