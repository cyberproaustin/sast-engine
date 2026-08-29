#!/usr/bin/env bash
# What the engine can SEE, measured without a single verdict.
#
#   loop/bin/coverage.sh <repo-dir> [name]
#
# Four numbers, none of which needs an adjudicator, a reviewer, or a rule to be any good:
#
#   routes      entry points enumerated, against path()/re_path()/router.register()/
#               decorators counted from source. Over 100% is normal and not an error: one
#               registration answers several verbs and a router expands into six.
#   unbound     calls the frontend could not bind to a definition, as a share of the calls
#               it did bind plus those it did not. NOT the external count: a Django or
#               Express import SHOULD be external, and counting those measured 88% on an
#               application whose real problem was elsewhere. This counts the ones that
#               looked first-party and still did not resolve. Every one is a hop dataflow
#               stops at.
#   unreached   functions that read caller-supplied input and that no enumerated entry
#               point reaches. The engine's own admission of blindness (ADR-003), and the
#               single number that best predicted where batch 3 went wrong.
#
# Coverage is the honest half of this project's measurements. Precision on a surface you
# have enumerated an eighth of is not a statement about an engine, and batch 3 spent hours
# of adjudication discovering that five of ten repositories could not see themselves.
# This costs seconds and needs no model at all.
set -uo pipefail
REPO="${1:?usage: coverage.sh <repo-dir> [name]}"
NAME="${2:-$(basename "$(dirname "$REPO")")}"
ENG=/home/austin/development/projects/sast-engine
IR=$(mktemp /home/austin/.sast-loop/cov-XXXXXX.json)
trap 'rm -f "$IR"' EXIT

# The language the scan RECORDED, never a fresh file count. Counting picked TypeScript for
# plane (3295 Angular/Next files against 653 Django ones) and read 3% of an application
# whose API is entirely Python; paperless-ngx read 0% the same way. This is the third time
# a file-count language guess has produced a number that looked like an engine failure.
LANG=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['lang'])" \
       "$(dirname "$REPO")/meta.json" 2>/dev/null)
if [ -z "$LANG" ]; then
  py=$(find "$REPO" -name '*.py' -not -path '*/node_modules/*' 2>/dev/null | wc -l)
  ts=$(find "$REPO" \( -name '*.ts' -o -name '*.tsx' \) -not -path '*/node_modules/*' 2>/dev/null | wc -l)
  [ "$py" -ge "$ts" ] && LANG=py || LANG=ts
fi
if [ "$LANG" = "py" ]; then
  python3 "$ENG/frontends/python/src/main.py" "$REPO" --out "$IR" >/dev/null 2>&1
else
  node --max-old-space-size=10240 "$ENG/frontends/typescript/src/index.ts" "$REPO" --out "$IR" >/dev/null 2>&1
fi
[ -s "$IR" ] || { printf '%-16s LOWER_FAIL\n' "$NAME"; exit 1; }

# Declared is PYTHON ONLY and says so. `path()` is a reliable marker for a Django route;
# TypeScript has no equivalent, because a route may be a tRPC procedure, a Next.js file
# path, a GraphQL field or an Express string, and counting decorators read saleor at 2032%
# and rallly at 1021%. A ratio against a denominator that does not mean anything is worse
# than no ratio. For TypeScript the honest coverage signal is `unreached`, which the engine
# computes for itself and which needs no grep at all.
if [ "$LANG" = "py" ]; then
  declared=$(( $(grep -rhoE "\b(path|re_path|url)\(" --include='*.py' "$REPO" 2>/dev/null | wc -l) \
            + $(grep -rhoE "router\.register\(|@(router|app)\.(get|post|put|patch|delete)\(" --include='*.py' "$REPO" 2>/dev/null | wc -l) ))
else
  declared=0
fi

SAST=${SAST:-/home/austin/.sast-loop/sast-cov}
[ -x "$SAST" ] || go build -C "$ENG/core" -o "$SAST" ./cmd/sast >/dev/null 2>&1
UNREACHED=$("$SAST" -ir "$IR" -format text 2>/dev/null \
  | grep -oE "INCOMPLETE: [0-9]+ function\(s\) read caller-supplied" | grep -oE "[0-9]+" | head -1)

python3 - "$IR" "$NAME" "$declared" "${UNREACHED:-0}" <<'PY'
import json,sys
ir=json.load(open(sys.argv[1])); name=sys.argv[2]; declared=int(sys.argv[3]); unreached=int(sys.argv[4])
eps=ir.get("entryPoints",[])
calls=[c for f in ir.get("functions",[]) for c in (f.get("calls") or [])]
kinds=[(c.get("callee") or {}).get("kind") for c in calls]
local=kinds.count("local"); unbound=kinds.count("unresolved")
pct=lambda a,b: f"{100*a/b:.0f}%" if b else "-"
route_col = f"{len(eps):>5}/{declared:<5} {pct(len(eps),declared):>5}" if declared else f"{len(eps):>5}/{'  -':<5} {'   -':>5}"
print(f"{name:<16} routes {route_col}   "
      f"unbound {unbound:>5}/{local+unbound:<6} {pct(unbound,local+unbound):>4}   "
      f"unreached {unreached:>5}")
PY
