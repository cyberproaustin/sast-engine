#!/usr/bin/env python3
"""Re-key the verdicts a fingerprint change split apart.

  python3 validation/rekey_fingerprints.py [--check]

A verdict is keyed by a fingerprint, so changing how a fingerprint is computed orphans
every verdict it changes. That is the reason `Finding.Discriminator` is appended only when
a rule HAS one: a rule that already distinguishes its siblings hashes exactly as it always
did, and 120 of the ledger's 131 rows never move.

Eleven do, and they are the ones the change was for. A call shape that judges the CALL
rather than an argument -- `Always` ("this call is a defect by existing") and `MissingArg`
("this argument was never supplied") -- recorded only the symbol, so every sibling in one
function came out identical. Those two forms emit CWE-209 (development-error-handler),
548, 477, 780, 378, 1022 and 494, and no other rule does; of the ledger's 61 hand
adjudications only the three juice-shop CWE-548 rows carry one, and of the 70 loop
adjudications only the eight CWE-1022 rows do.

Measured rather than reasoned: both engine builds were run over one lowering of each
repository and the results joined by file, line and rule. 60 juice-shop results before, 60
after, the same set; 77 results across the ten loop repositories before and after, the same
set. Twelve fingerprints changed, eleven of them in this ledger, and they are below.

The old value stays on the row as `supersedes`. A verdict is a record of somebody reading
code, and rewriting its key without saying so would leave no way to tell a re-keyed row
from a re-adjudicated one -- and `ingest_loop.py` needs it too, because artifacts written
by the previous build still name the old fingerprint and a verdict already recorded must
not be asked for a second time (that is the entire point of the ledger).
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
LEDGER = HERE / "verdicts.json"

# juice-shop's five `serveIndex(...)` calls in server.ts all hashed to ef8b2b65e604649e.
# Three were adjudicated separately and each says which directory it is about, which is
# how each row finds its own new key. server.ts:268 `/infrastructure` and :292
# `/.well-known` were never adjudicated and are not here.
COLLIDED = "ef8b2b65e604649e"
BY_DIRECTORY = {
    "/ftp": "a36260948059010a",  # server.ts:288  serveIndex('ftp')
    "/encryptionkeys": "5426636c9412f616",  # server.ts:296  serveIndex('encryptionkeys')
    "/support/logs": "b2b9e996ddc1dc8c",  # server.ts:300  serveIndex('logs')
}

# The eight `window.open` findings, one to one: `opener-reachable` matched on the call
# itself, so two calls in one component were one fingerprint waiting to happen.
ONE_TO_ONE = {
    "0b92da144e04dc95": "193146357cb1e830",  # linkwarden apps/web/lib/client/openLink.ts
    "33c9ed34c4037d88": "1233910175e6bc97",  # linkwarden apps/web/pages/collections/[id].tsx
    "3326184f76011994": "e8335633a6fcec85",  # umami .../heatmaps/HeatmapsPage.tsx
    "410ea9d9f4da1df6": "5b4d1d139ea1dc38",  # umami .../replays/ReplaysPage.tsx
    "bf847c8a5e7948d3": "c6f969090b2669de",  # umami .../settings/WebsiteReplaySettings.tsx
    "ae4450b609526f31": "56456657dadf7919",  # umami src/components/input/SettingsButton.tsx
    "77898b21e15682fb": "acc88a3934e35930",  # unleash .../FeedbackNPS/FeedbackNPS.tsx
    "f88704d024dff36c": "f5751e6a8e3e2b2a",  # unleash .../layout/Error/LayoutError.tsx
}


def rekey(rows):
    """Returns the number of rows moved. Idempotent: a row already carrying `supersedes`
    has been moved and is left alone."""
    moved = 0
    for row in rows:
        if "supersedes" in row:
            continue
        fp = row["fingerprint"]
        new = ONE_TO_ONE.get(fp)
        if new is None and fp == COLLIDED:
            for directory, candidate in BY_DIRECTORY.items():
                if directory in (row.get("reason") or ""):
                    new = candidate
                    break
            else:
                raise SystemExit(
                    f"a row on the collided fingerprint names no directory: {row.get('reason')!r}\n"
                    "Re-keying it would guess which of the three findings it judged."
                )
        if new is None:
            continue
        row["supersedes"] = fp
        row["fingerprint"] = new
        moved += 1
    return moved


def main(check):
    doc = json.loads(LEDGER.read_text())
    rows = doc["verdicts"]
    before = len(rows)
    keys_before = [r["fingerprint"] for r in rows]

    moved = rekey(rows)

    after = len(rows)
    keys_after = [r["fingerprint"] for r in rows]
    if before != after:
        raise SystemExit(f"the ledger changed size: {before} -> {after}")
    duplicates_before = before - len(set(keys_before))
    duplicates_after = after - len(set(keys_after))

    print(f"verdicts: {before} before, {after} after")
    print(f"re-keyed: {moved}")
    print(f"rows sharing a key with another row: {duplicates_before} before, {duplicates_after} after")
    if check:
        print("--check: nothing written")
        return 0
    LEDGER.write_text(json.dumps(doc, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main("--check" in sys.argv[1:]))
