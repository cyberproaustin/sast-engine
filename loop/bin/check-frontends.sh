#!/usr/bin/env bash
# `make bench` scores the Go core against pre-generated IR goldens, so a frontend that
# crashes on every real repository still passes every corpus at 1.00/1.00. That happened:
# two branches auto-merged into a call with two arguments against a definition taking one,
# 203 corpora stayed green, and the Python frontend raised NameError on the first Django
# repository lowered. Nothing in the gates ran a frontend against real code.
#
#   loop/bin/check-frontends.sh
#
# Lowers one real repository per frontend and fails if either cannot produce entry points.
set -uo pipefail
ENG=/home/austin/development/projects/sast-engine
rc=0
py=$(python3 "$ENG/frontends/python/src/main.py" /home/austin/.sast-loop/work/doccano/repo \
      --out /home/austin/.sast-loop/.fe-py.json 2>&1 | tail -1)
n=$(python3 -c "import json;print(len(json.load(open('/home/austin/.sast-loop/.fe-py.json')).get('entryPoints',[])))" 2>/dev/null || echo 0)
[ "$n" -ge 30 ] && echo "python OK ($n entry points)" || { echo "PYTHON FRONTEND BROKEN: $py"; rc=1; }
ts=$(node --max-old-space-size=10240 "$ENG/frontends/typescript/src/index.ts" \
      /home/austin/.sast-loop/work/reactive-resume/repo --out /home/austin/.sast-loop/.fe-ts.json 2>&1 | tail -1)
m=$(python3 -c "import json;print(len(json.load(open('/home/austin/.sast-loop/.fe-ts.json')).get('entryPoints',[])))" 2>/dev/null || echo 0)
[ "$m" -ge 20 ] && echo "typescript OK ($m entry points)" || { echo "TYPESCRIPT FRONTEND BROKEN: $ts"; rc=1; }
rm -f /home/austin/.sast-loop/.fe-py.json /home/austin/.sast-loop/.fe-ts.json
exit $rc
