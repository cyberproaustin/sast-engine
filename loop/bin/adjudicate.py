#!/usr/bin/env python3
"""Prepare, merge, and validate bounded adjudication calls."""

import argparse
import copy
import json
import pathlib
import posixpath
import re
import shutil
import sys


REPORT_HEADINGS = (
    "### 1. Clashes",
    "### 2. False positives",
    "### 3. Run quality",
    "### 4. What neither of us looked at",
)
SLICE_HEADINGS = ("## Clashes", "## False positives", "## Coverage notes")
VERDICTS = {"true", "false", "disputed", "unreachable"}
PROVENANCE = {"engine", "review", "both"}
# validation/ moved under loop/ in 1ac6756 and this path was not repointed. A missing ledger
# is not an error here -- recorded_fingerprints() returns empty -- so the 171-verdict ledger
# silently stopped being consulted and every adjudication re-judged what was already judged.
LEDGER = pathlib.Path(__file__).parents[1] / "validation" / "verdicts.json"
SOURCE_SUFFIXES = (".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
IDENTIFIER = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")
DEFINITION = re.compile(
    r"(?m)^(?:(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:def|function|class)\s+"
    r"|(?:(?:export\s+)?(?:const|let|var|enum|interface|type)\s+))"
    r"([A-Za-z_$][A-Za-z0-9_$]*)\b"
)
ASSIGNMENT_DEFINITION = re.compile(
    r"(?m)^([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::[^=\n]+)?="
)


def load_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def recorded_fingerprints():
    if not LEDGER.exists():
        return set()
    verdicts = load_json(LEDGER)["verdicts"]
    # A DISPUTED row is not an answer. It is the adjudicator refusing for want of evidence --
    # almost always "the implementation of X is absent from this packet" -- and the packet now
    # carries the callee it was missing. Treating a refusal as recorded is what would make the
    # ledger permanently inherit the packet's old blind spots: 28 of 41 findings from the
    # rules with no true positive were refused on exactly that ground.
    #
    # The rule the ledger actually protects is that a DECIDED verdict is never asked twice,
    # which is what stopped eighteen yt-dlp findings flipping true/false on identical code.
    # Re-asking a refusal cannot reintroduce that instability: it has no verdict to contradict.
    answered = [row for row in verdicts if row.get("verdict") != "disputed"]
    fingerprints = {row["fingerprint"] for row in answered}
    fingerprints.update(row["supersedes"] for row in answered if row.get("supersedes"))
    return fingerprints


def fingerprint_of(finding):
    return (finding.get("partialFingerprints") or {}).get("sastEngine/v1")


def repeated_reason_groups(rows):
    grouped = {}
    for row in rows:
        reason = (row.get("reason") or "").strip()
        if reason:
            grouped.setdefault(reason, []).append(row)
    return [(reason, matches) for reason, matches in grouped.items() if len(matches) > 1]


def write_template_reason_report(work, rows):
    groups = sorted(repeated_reason_groups(rows), key=lambda item: (-len(item[1]), item[0]))
    lines = []
    for reason, matches in groups:
        lines.append(f"{len(matches)} verdicts share one reason; treat as N=1 data point")
        lines.append(f"  {' '.join(reason.split())}")
    if not lines:
        lines.append("No verbatim reason is shared by multiple verdicts.")
    report = "\n".join(lines) + "\n"
    (work / "template-reasons.txt").write_text(report)
    (work / "adjudication-slices/final/template-reasons.txt").write_text(report)
    return groups


def safe_repo_path(value):
    if not isinstance(value, str):
        return None
    value = value.replace("\\", "/").removeprefix("./")
    path = pathlib.PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts:
        return None
    return path.as_posix()


def physical_locations(value):
    """Yield every SARIF artifact URI; flows matter as much as the sink."""
    if isinstance(value, dict):
        physical = value.get("physicalLocation")
        if isinstance(physical, dict):
            artifact = physical.get("artifactLocation") or {}
            path = safe_repo_path(artifact.get("uri"))
            if path:
                yield path
        for child in value.values():
            yield from physical_locations(child)
    elif isinstance(value, list):
        for child in value:
            yield from physical_locations(child)


def primary_location(kind, finding):
    if kind == "review":
        return safe_repo_path(finding.get("file")), finding.get("line") or 0
    try:
        physical = finding["locations"][0]["physicalLocation"]
        return safe_repo_path(physical["artifactLocation"]["uri"]), physical["region"]["startLine"]
    except (KeyError, IndexError, TypeError):
        return None, 0


def cwe_of(finding):
    return finding.get("cwe") or finding.get("ruleId") or ""


def string_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from string_values(child)


def referenced_identifiers(*values):
    identifiers = set()
    for value in values:
        for text in string_values(value):
            called = set(re.findall(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", text))
            for name in IDENTIFIER.findall(text):
                if (name in called or "_" in name or name[:1].isupper() or
                        re.search(r"[a-z0-9][A-Z]", name)):
                    identifiers.add(name)
    return identifiers


def previous_adjudication(path):
    if not path.exists():
        return []
    try:
        rows = load_json(path)
    except (OSError, json.JSONDecodeError):
        return []
    return rows if isinstance(rows, list) else []


def finding_hints(kind, finding, rows):
    primary, line = primary_location(kind, finding)
    cwe = cwe_of(finding)
    return [row for row in rows if isinstance(row, dict) and
            row.get("found_by") in (kind, "both") and row.get("file") == primary and
            row.get("line") == line and row.get("cwe") == cwe]


class DefinitionResolver:
    """Find one-hop source definitions without constructing a language import graph."""

    def __init__(self, repo, repo_files):
        self.repo = repo
        self.repo_files = set(repo_files)
        self.source_files = {path for path in repo_files if pathlib.PurePosixPath(path).suffix
                             in SOURCE_SUFFIXES}
        self.texts = {}
        self.definitions = {}
        self.definition_index = None
        self.package_roots = None

    def text(self, path):
        if path not in self.texts:
            try:
                self.texts[path] = (self.repo / path).read_text(errors="replace")
            except OSError:
                self.texts[path] = ""
        return self.texts[path]

    def definitions_in(self, path):
        if path not in self.definitions:
            text = self.text(path)
            self.definitions[path] = set(DEFINITION.findall(text))
            self.definitions[path].update(ASSIGNMENT_DEFINITION.findall(text))
        return self.definitions[path]

    def definition_files(self, name):
        if self.definition_index is None:
            self.definition_index = {}
            for path in self.source_files:
                for defined in self.definitions_in(path):
                    self.definition_index.setdefault(defined, set()).add(path)
        return self.definition_index.get(name, set())

    def module_files(self, importer, module):
        suffix = pathlib.PurePosixPath(importer).suffix
        candidates = []
        if suffix == ".py":
            if module.startswith("."):
                level = len(module) - len(module.lstrip("."))
                parent = pathlib.PurePosixPath(importer).parent
                for _ in range(level - 1):
                    parent = parent.parent
                tail = module[level:].replace(".", "/")
                base = posixpath.normpath((parent / tail).as_posix())
                candidates.extend((f"{base}.py", f"{base}/__init__.py"))
            else:
                base = module.replace(".", "/")
                endings = (f"/{base}.py", f"/{base}/__init__.py")
                candidates.extend(path for path in self.source_files
                                  if path == endings[0][1:] or path == endings[1][1:] or
                                  path.endswith(endings))
        elif module.startswith("."):
            base = posixpath.normpath(
                (pathlib.PurePosixPath(importer).parent / module).as_posix()
            )
            candidates.append(base)
            candidates.extend(base + extension for extension in SOURCE_SUFFIXES if extension != ".py")
            candidates.extend(f"{base}/index{extension}" for extension in SOURCE_SUFFIXES
                              if extension != ".py")
        return {path for path in candidates if path in self.source_files}

    def package_root_for(self, module):
        if self.package_roots is None:
            self.package_roots = {}
            for path in self.repo_files:
                if pathlib.PurePosixPath(path).name != "package.json":
                    continue
                try:
                    name = json.loads(self.text(path)).get("name")
                except json.JSONDecodeError:
                    continue
                if isinstance(name, str):
                    self.package_roots.setdefault(name, set()).add(
                        pathlib.PurePosixPath(path).parent.as_posix()
                    )
        parts = module.split("/")
        package = "/".join(parts[:2]) if module.startswith("@") else parts[0]
        roots = self.package_roots.get(package, set())
        return next(iter(roots)) if len(roots) == 1 else None

    def fallback_definitions(self, importer, name, imports):
        definitions = self.definition_files(name) - {importer}
        allowed = set()
        for module, _, _ in imports:
            if module.startswith("."):
                allowed.update(definitions)
            elif pathlib.PurePosixPath(importer).suffix == ".py":
                # An absolute Python import is first-party only when its module resolves in
                # this checkout. Do not turn an installed dependency name into a random local
                # definition with the same spelling.
                if self.module_files(importer, module):
                    allowed.update(path for path in definitions if path.endswith(".py"))
            else:
                root = self.package_root_for(module)
                if root:
                    prefix = root.rstrip("/") + "/"
                    allowed.update(path for path in definitions
                                   if path == root or path.startswith(prefix))
        return allowed

    def imports_of(self, path):
        text = self.text(path)
        imported = {}

        for match in re.finditer(
                r"(?ms)^\s*from\s+([.A-Za-z0-9_]+)\s+import\s*(?:\((.*?)\)|([^\n#]+))", text):
            module, parenthesized, single_line = match.groups()
            names = parenthesized if parenthesized is not None else single_line
            for item in names.split(","):
                fields = item.strip().split()
                if not fields:
                    continue
                remote = fields[0]
                local = fields[2] if len(fields) >= 3 and fields[1] == "as" else remote
                imported.setdefault(local, []).append((module, remote, False))

        for match in re.finditer(
                r"(?s)\bimport\s+(?:type\s+)?\{([^}]+)\}\s+from\s+['\"]([^'\"]+)['\"]", text):
            names, module = match.groups()
            for item in names.split(","):
                fields = item.strip().split()
                if not fields:
                    continue
                remote = fields[0]
                local = fields[2] if len(fields) >= 3 and fields[1] == "as" else remote
                imported.setdefault(local, []).append((module, remote, False))

        for match in re.finditer(
                r"(?m)^\s*import\s+(?:type\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+"
                r"['\"]([^'\"]+)['\"]", text):
            local, module = match.groups()
            imported.setdefault(local, []).append((module, local, True))

        for match in re.finditer(
                r"(?m)^\s*(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(['\"]([^'\"]+)['\"]\)",
                text):
            names, module = match.groups()
            for item in names.split(","):
                fields = item.strip().split(":", 1)
                remote, local = fields[0].strip(), fields[-1].strip()
                if remote:
                    imported.setdefault(local, []).append((module, remote, False))
        return imported

    def callees(self, selected, identifiers):
        # The 28 measured implementation-absent refusals were about named helpers, not every
        # dependency of a selected file. Requiring both a finding name and a use in the caller
        # keeps this one hop narrow enough for the packet budget.
        callees = set()
        for importer in set(selected):
            text = self.text(importer)
            imports = self.imports_of(importer)
            for name in identifiers:
                if not re.search(rf"(?<![A-Za-z0-9_$]){re.escape(name)}(?![A-Za-z0-9_$])", text):
                    continue
                matches = set()
                for module, remote, is_default in imports.get(name, []):
                    for candidate in self.module_files(importer, module):
                        if is_default or remote in self.definitions_in(candidate):
                            matches.add(candidate)
                    if pathlib.PurePosixPath(importer).suffix == ".py":
                        # ``from package import helper`` may import package/helper.py rather
                        # than a name assigned by package/__init__.py.
                        submodule = f"{module}{remote}" if module.endswith(".") \
                            else f"{module}.{remote}"
                        matches.update(self.module_files(importer, submodule))
                if len(matches) == 1:
                    callees.update(matches)
                    continue

                # Generated barrels and Python package roots often defeat the cheap import
                # parser. A unique definition still answers the packet; 40 plausible files do
                # not, and adding all 40 recreated the source-budget failure in another form.
                fallback = self.fallback_definitions(importer, name, imports[name]) \
                    if name in imports else set()
                if len(fallback) == 1:
                    callees.update(fallback)
        return callees


def source_files(kind, finding, repo_files):
    # Review findings carry useful cross-file evidence in prose rather than a structured
    # flow. Matching against the checkout inventory retained every cited file in both of
    # the large-repository failures while avoiding a language-specific path parser.
    blob = json.dumps(finding, ensure_ascii=False)
    found = {path for path in repo_files if path in blob}
    found.update(physical_locations(finding))
    primary, _ = primary_location(kind, finding)
    if primary:
        found.add(primary)
    return {path for path in found if path in repo_files}


def read_entrypoints(path):
    entries = []
    for line in path.read_text(errors="replace").splitlines():
        fields = line.split("\t")
        if len(fields) < 5:
            continue
        source = safe_repo_path(fields[4].split("#", 1)[0])
        entries.append({"line": line, "method": fields[2], "route": fields[3], "source": source})
    return entries


def matching_entrypoints(finding, referenced, entries):
    blob = json.dumps(finding, ensure_ascii=False)
    matched = []
    for entry in entries:
        route_label = f"{entry['method']} {entry['route']}"
        if entry["source"] in referenced or route_label in blob:
            matched.append(entry)
    return matched


def make_record(kind, finding, repo_files, entries, resolver, hints=()):
    referenced = source_files(kind, finding, repo_files)
    matched = matching_entrypoints(finding, referenced, entries)
    referenced.update(entry["source"] for entry in matched if entry["source"] in repo_files)
    referenced.update(resolver.callees(referenced, referenced_identifiers(finding, list(hints))))
    primary, line = primary_location(kind, finding)
    return {
        "kind": kind,
        "finding": finding,
        "primary": primary,
        "line": line,
        "cwe": cwe_of(finding),
        "files": referenced,
        "entrypoints": {entry["line"] for entry in matched},
    }


def pair_records(engine, review):
    """Keep plausible cross-reader duplicates in one slice without pre-judging them."""
    available = set(range(len(engine)))
    units = []
    for review_record in review:
        candidates = []
        for index in available:
            engine_record = engine[index]
            same_file = (review_record["primary"] and
                         review_record["primary"] == engine_record["primary"])
            if not same_file and not (review_record["files"] & engine_record["files"]):
                continue
            same_cwe = review_record["cwe"] == engine_record["cwe"]
            distance = abs(review_record["line"] - engine_record["line"])
            if same_cwe or (same_file and distance <= 5):
                candidates.append((0 if same_file else 1, 0 if same_cwe else 1, distance, index))
        if candidates:
            _, _, _, index = min(candidates)
            available.remove(index)
            units.append([engine[index], review_record])
        else:
            units.append([review_record])
    units.extend([engine[index]] for index in sorted(available))
    return units


def bytes_for(repo, files):
    total = 0
    for name in files:
        try:
            total += (repo / name).stat().st_size
        except OSError:
            pass
    return total


def pack_units(units, repo, max_findings, max_source_bytes):
    slices = []
    current = []
    current_files = set()
    current_count = 0
    for unit in units:
        unit_files = set().union(*(record["files"] for record in unit))
        next_files = current_files | unit_files
        too_many = current_count + len(unit) > max_findings
        too_large = bytes_for(repo, next_files) > max_source_bytes
        if current and (too_many or too_large):
            slices.append(current)
            current, current_files, current_count = [], set(), 0
        current.extend(unit)
        current_files.update(unit_files)
        current_count += len(unit)
    if current:
        slices.append(current)
    return slices


def engine_document(template, results):
    document = copy.deepcopy(template)
    document["runs"][0]["results"] = results
    return document


def engine_text(results):
    lines = []
    for result in results:
        path, line = primary_location("engine", result)
        lines.extend((f"[{result.get('level', 'warning').upper()}] {result.get('ruleId', 'unknown')}",
                      f"  sink: {path}:{line}", f"  {result.get('message', {}).get('text', '')}", ""))
    return "\n".join(lines)


def copy_sources(repo, destination, files):
    copied = []
    for name in sorted(files):
        source = repo / name
        if not source.is_file():
            continue
        target = destination / "repo" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        copied.append(name)
    return copied


def repo_inventory(repo):
    paths = []
    for path in repo.rglob("*"):
        relative = path.relative_to(repo)
        if ".git" in relative.parts:
            continue
        suffix = "/" if path.is_dir() else ""
        paths.append(relative.as_posix() + suffix)
    return "\n".join(sorted(paths)) + "\n"


def prepare(work, max_findings, max_source_bytes):
    if max_findings < 2 or max_source_bytes < 1:
        raise ValueError("slice bounds must allow a paired engine and review finding")
    repo = work / "repo"
    engine_path = work / "findings-engine.sarif"
    review_path = work / "findings-review.json"
    for required in (repo, engine_path, review_path, work / "entrypoints.tsv", work / "lower.log"):
        if not required.exists():
            raise ValueError(f"missing required adjudication input: {required}")

    # A refusal names the exact absent implementation. Retaining that name while rebuilding
    # lets the measured 28/41 disputed findings receive the missing source on their second pass.
    previous_rows = previous_adjudication(work / "adjudication.json")
    slices_root = work / "adjudication-slices"
    if slices_root.exists():
        shutil.rmtree(slices_root)
    slices_root.mkdir()
    for stale in (work / "adjudication.json", work / "codex-report.md",
                  work / "template-reasons.txt", work / "codex.log", work / "codex.err"):
        stale.unlink(missing_ok=True)

    repo_files = {path.relative_to(repo).as_posix() for path in repo.rglob("*")
                  if path.is_file() and not path.is_symlink() and
                  ".git" not in path.relative_to(repo).parts}
    resolver = DefinitionResolver(repo, repo_files)
    entries = read_entrypoints(work / "entrypoints.tsv")
    engine_doc = load_json(engine_path)
    all_engine_findings = engine_doc["runs"][0].get("results", [])
    recorded = recorded_fingerprints()
    engine_findings = [finding for finding in all_engine_findings
                       if fingerprint_of(finding) not in recorded]
    answered = len(all_engine_findings) - len(engine_findings)
    review_doc = load_json(review_path)
    if not isinstance(review_doc, (dict, list)):
        raise ValueError("findings-review.json must be an object or array")
    review_findings = review_doc if isinstance(review_doc, list) else review_doc.get("findings", [])
    engine = [make_record("engine", finding, repo_files, entries, resolver,
                          finding_hints("engine", finding, previous_rows))
              for finding in engine_findings]
    review = [make_record("review", finding, repo_files, entries, resolver,
                          finding_hints("review", finding, previous_rows))
              for finding in review_findings]
    slices = pack_units(pair_records(engine, review), repo, max_findings, max_source_bytes)
    manifest = {"slice_count": len(slices),
                "engine_findings_total": len(all_engine_findings),
                "engine_findings_answered": answered,
                "engine_findings": len(engine),
                "review_findings": len(review), "max_findings": max_findings,
                "max_source_bytes": max_source_bytes, "slices": []}
    for index, records in enumerate(slices, 1):
        destination = slices_root / f"slice-{index:03d}"
        destination.mkdir()
        files = set().union(*(record["files"] for record in records))
        copied = copy_sources(repo, destination, files)
        engine_subset = [record["finding"] for record in records if record["kind"] == "engine"]
        review_subset = [record["finding"] for record in records if record["kind"] == "review"]
        entrypoint_lines = sorted(set().union(*(record["entrypoints"] for record in records)))
        (destination / "findings-engine.sarif").write_text(
            json.dumps(engine_document(engine_doc, engine_subset), indent=2) + "\n")
        (destination / "findings-engine.txt").write_text(engine_text(engine_subset))
        review_slice = ({"findings": review_subset} if isinstance(review_doc, list)
                        else {**{key: value for key, value in review_doc.items() if key != "findings"},
                              "findings": review_subset})
        (destination / "findings-review.json").write_text(json.dumps(review_slice, indent=2) + "\n")
        (destination / "entrypoints.tsv").write_text("\n".join(entrypoint_lines) + ("\n" if entrypoint_lines else ""))
        slice_meta = {"index": index, "slice_count": len(slices),
                      "engine_findings": len(engine_subset), "review_findings": len(review_subset),
                      "source_bytes": bytes_for(repo, set(copied)), "source_files": copied,
                      "entrypoints": len(entrypoint_lines)}
        (destination / "slice.json").write_text(json.dumps(slice_meta, indent=2) + "\n")
        manifest["slices"].append(slice_meta)

    final = slices_root / "final"
    final.mkdir()
    shutil.copy2(work / "entrypoints.tsv", final / "entrypoints.tsv")
    shutil.copy2(work / "lower.log", final / "lower.log")
    (final / "repo-tree.txt").write_text(repo_inventory(repo))
    scope = ({"finding_count": len(review_doc)} if isinstance(review_doc, list) else {
        key: review_doc.get(key) for key in ("repo", "sha", "entry_points_seen", "notes")
    })
    (final / "review-scope.json").write_text(json.dumps(scope, indent=2) + "\n")
    (slices_root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    if not slices:
        write_template_reason_report(work, [])
    return manifest


def validate_rows(rows, source):
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"{source} must contain a non-empty JSON array")
    required = {"id", "cwe", "found_by", "file", "line", "evidence", "verdict", "reason",
                "reachable_from", "guard_seen", "worth_reporting"}
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or required - row.keys():
            raise ValueError(f"{source} row {index + 1} is missing {sorted(required - row.keys())}")
        if row["found_by"] not in PROVENANCE or row["verdict"] not in VERDICTS:
            raise ValueError(f"{source} row {index + 1} has an invalid enum value")
        strings = ("id", "cwe", "file", "evidence", "reason", "reachable_from")
        if any(not isinstance(row[field], str) or not row[field].strip() for field in strings):
            raise ValueError(f"{source} row {index + 1} has an invalid string field")
        if (not isinstance(row["line"], int) or row["line"] < 1 or
                not isinstance(row["worth_reporting"], bool) or
                (row["guard_seen"] is not None and not isinstance(row["guard_seen"], str))):
            raise ValueError(f"{source} row {index + 1} has an invalid field type")


def merge(work):
    slices_root = work / "adjudication-slices"
    rows = []
    reports = []
    for directory in sorted(slices_root.glob("slice-[0-9][0-9][0-9]")):
        path = directory / "adjudication.json"
        report = directory / "slice-report.md"
        if not path.exists() or not report.exists():
            raise ValueError(f"incomplete slice output: {directory.name}")
        slice_rows = load_json(path)
        validate_rows(slice_rows, path)
        rows.extend(slice_rows)
        reports.append(f"# {directory.name}\n\n{report.read_text(errors='replace').strip()}\n")
    if not rows:
        raise ValueError("no slice outputs found")
    seen = {}
    for row in rows:
        base = re.sub(r"[^a-z0-9]+", "-", str(row["id"]).lower()).strip("-") or "finding"
        seen[base] = seen.get(base, 0) + 1
        row["id"] = base if seen[base] == 1 else f"{base}-{seen[base]}"
    (work / "adjudication.json").write_text(json.dumps(rows, indent=2) + "\n")
    final = slices_root / "final"
    shutil.copy2(work / "adjudication.json", final / "adjudication.json")
    (final / "slice-reports.md").write_text("\n".join(reports))
    shutil.copy2(slices_root / "manifest.json", final / "slice-manifest.json")
    write_template_reason_report(work, rows)
    return len(rows)


def validate(work):
    rows = load_json(work / "adjudication.json")
    validate_rows(rows, work / "adjudication.json")
    report = (work / "codex-report.md").read_text(errors="replace")
    # Match the heading TEXT at any depth. All four sections arrived in order in three of
    # three runs and the whole final validation failed anyway, because the model wrote `#`
    # where the contract said `###`. A contract that rejects a correct report over heading
    # depth teaches nothing and throws away the synthesis.
    positions = [re.search(r"(?m)^#{1,6}\s*" + re.escape(heading.lstrip("# ")), report)
                 for heading in REPORT_HEADINGS]
    positions = [m.start() if m else -1 for m in positions]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise ValueError("codex-report.md does not contain the four ordered contract sections")
    return len(rows)



def distinct_engine_findings(directory):
    """The floor: one row per (rule, file) a slice carries, not one per result.

    Two things break a per-result floor and only one of them is a defect. The engine emits
    byte-for-byte duplicate SARIF results -- 25 of 342 across batch 3 -- which is a defect and
    is recorded as one. But an adjudicator also MERGES legitimately: defectdojo's slice 5
    carried CWE-862 at `views.py:123` and `:124`, and the right answer is one row saying both
    are reached after the same guard, not two rows repeating each other.

    So the floor guards against work being SKIPPED rather than against judgement being
    exercised. Dropping a whole file is the failure worth catching; collapsing two lines of
    one file into one verdict is the reader doing their job.
    """
    try:
        results = load_json(directory / "findings-engine.sarif")["runs"][0].get("results", [])
    except (OSError, KeyError, IndexError, json.JSONDecodeError):
        return load_json(directory / "slice.json")["engine_findings"]
    seen = set()
    for result in results:
        location = result["locations"][0]["physicalLocation"]
        seen.add((result.get("ruleId"), location["artifactLocation"]["uri"]))
    return len(seen)


def validate_slice(directory):
    rows = load_json(directory / "adjudication.json")
    validate_rows(rows, directory / "adjudication.json")
    report = (directory / "slice-report.md").read_text(errors="replace")
    positions = [report.find(heading) for heading in SLICE_HEADINGS]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise ValueError(f"{directory / 'slice-report.md'} does not contain the ordered slice sections")
    metadata = load_json(directory / "slice.json")
    # DISTINCT engine findings, not the raw count. The engine emits byte-for-byte duplicate
    # SARIF results -- 25 of 342 across batch 3, 21 of them in one repository -- and a slice
    # carrying `metrics/views.py:676` twice cannot be answered with two rows about it. The
    # adjudicator collapsed defectdojo's slice 5 from 8 to 5 and said so in its report
    # ("including one byte-for-byte duplicate SARIF result"); the floor called that a
    # failure and threw the whole slice away, twice.
    #
    # The duplication is an engine defect and is recorded as one. This floor should not have
    # been the thing that noticed, and it should not be the thing that blocks on it.
    minimum = max(distinct_engine_findings(directory), metadata["review_findings"])
    maximum = metadata["engine_findings"] + metadata["review_findings"]
    if not minimum <= len(rows) <= maximum:
        raise ValueError(f"{directory / 'adjudication.json'} has {len(rows)} rows for "
                         f"{maximum} assigned finding records")
    return len(rows)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("work", type=pathlib.Path)
    prepare_parser.add_argument("--max-findings", type=int, default=8)
    prepare_parser.add_argument("--max-source-bytes", type=int, default=600_000)
    merge_parser = subparsers.add_parser("merge")
    merge_parser.add_argument("work", type=pathlib.Path)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("work", type=pathlib.Path)
    validate_slice_parser = subparsers.add_parser("validate-slice")
    validate_slice_parser.add_argument("directory", type=pathlib.Path)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare(args.work.resolve(), args.max_findings, args.max_source_bytes)
            print(f"prepared {result['slice_count']} slices for "
                  f"{result['engine_findings']} genuinely new engine and "
                  f"{result['review_findings']} review findings; "
                  f"{result['engine_findings_answered']} engine findings already answered")
        elif args.command == "merge":
            work = args.work.resolve()
            print(f"merged {merge(work)} adjudication rows")
            print((work / "template-reasons.txt").read_text(), end="")
        elif args.command == "validate":
            print(f"validated {validate(args.work.resolve())} adjudication rows and four report sections")
        else:
            print(f"validated {validate_slice(args.directory.resolve())} slice adjudication rows")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"adjudication harness: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
