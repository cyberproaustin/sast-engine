#!/usr/bin/env bash
# Track B: the independent read. One repository, one reviewer, no sight of the engine.
#
#   loop/bin/review.sh <name> <workroot>
#
# The prompt says the reviewer will not be shown the engine's findings. That is a promise
# the harness has to keep rather than a request the reviewer has to honour: the review runs
# in its OWN directory holding nothing but `repo/`, so findings-engine.sarif is not merely
# unmentioned, it is not reachable. A reviewer shown a tool's output first confirms it and
# stops looking, and the whole value of this read is that it is independent.
set -uo pipefail
NAME="${1:?}"; WORK="${2:?}"
ENG=/home/austin/development/projects/sast-engine
SRC="$WORK/$NAME"; PEN="$WORK/$NAME/review"
[ -d "$SRC/repo" ] || { echo "$NAME REVIEW_FAIL no repo"; exit 1; }
rm -rf "$PEN"; mkdir -p "$PEN"
ln -s "$SRC/repo" "$PEN/repo"
cp "$ENG/loop/bin/review-prompt.md" "$PEN/prompt.md"
timeout 7200 codex exec --sandbox workspace-write --skip-git-repo-check \
  -c model_reasoning_effort="high" --cd "$PEN" - \
  >"$PEN/codex.log" 2>"$PEN/codex.err" <"$PEN/prompt.md"
rc=$?
if [ -s "$PEN/findings-review.json" ]; then
  cp "$PEN/findings-review.json" "$SRC/findings-review.json"
  n=$(python3 -c "import json,sys;d=json.load(open('$SRC/findings-review.json'));print(len(d if isinstance(d,list) else d.get('findings') or []))" 2>/dev/null || echo '?')
  echo "$NAME REVIEWED rc=$rc findings=$n"
else
  echo "$NAME REVIEW_FAIL rc=$rc no findings-review.json"; exit 1
fi
