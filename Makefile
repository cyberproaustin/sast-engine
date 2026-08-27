# The corpus lists are DERIVED from the fixtures, not written down. Four separate merges
# collapsed these two lines into one, and a corpus in the wrong list is lowered by the wrong
# frontend -- which fails as though a rule regressed. A list that cannot be written down
# cannot be merged wrongly.
#
# A corpus is Python when it holds more .py files than TypeScript ones. That is a fact about
# the fixture rather than a convention anyone has to remember.
CORPORA_ALL := $(notdir $(wildcard testdata/*))
PY_CORPORA  := $(foreach c,$(CORPORA_ALL),$(if $(shell test $$(find testdata/$(c) -name '*.py' | wc -l) -gt $$(find testdata/$(c) \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' -o -name '*.mjs' -o -name '*.mts' \) | wc -l) && echo y),$(c)))
TS_CORPORA  := $(filter-out $(PY_CORPORA),$(CORPORA_ALL))

FIXTURE := testdata/express-command-injection
GOLDEN  := core/internal/taint/testdata
IR_TMP  := .ir.json

.PHONY: help setup ir scan sarif baseline test bench testdata fmt clean

help:
	@echo "setup     install frontend dependencies"
	@echo "ir        lower the fixture and print Program IR"
	@echo "scan      lower the fixture, then analyze it (exit 1 on gating findings)"
	@echo "sarif     same as scan, SARIF output"
	@echo "baseline  record the fixture's findings, then show that a second run is clean"
	@echo "test      run the core test suite"
	@echo "bench     score every corpus (precision / recall)"
	@echo "testdata  regenerate the golden IR consumed by the core tests"
	@echo "fmt       gofmt the core"

setup:
	cd frontends/typescript && npm install
	@echo "python frontend uses the stdlib only"

ir:
	@node frontends/typescript/src/index.ts $(FIXTURE)

# The frontend and the core are separate processes on purpose: the IR is the only
# thing that crosses between them (ADR-001).
scan:
	@node frontends/typescript/src/index.ts $(FIXTURE) --out $(IR_TMP)
	@cd core && go run ./cmd/sast -ir ../$(IR_TMP)

sarif:
	@node frontends/typescript/src/index.ts $(FIXTURE) --out $(IR_TMP)
	@cd core && go run ./cmd/sast -ir ../$(IR_TMP) -format sarif

# Demonstrates the pipeline contract: a first run fails, a recorded run does not, and
# nothing was hidden to achieve it.
baseline:
	@node frontends/typescript/src/index.ts $(FIXTURE) --out $(IR_TMP)
	@cd core && go run ./cmd/sast -ir ../$(IR_TMP) -write-baseline ../.sast-baseline.json
	@cd core && go run ./cmd/sast -ir ../$(IR_TMP) -baseline ../.sast-baseline.json

test:
	cd core && go test ./... -count=1
	@[ -f loop/bin/test_adjudicate.py ] && python3 loop/bin/test_adjudicate.py || true

# A corpus in the wrong list is lowered by the wrong frontend and fails in a way that looks
# like a rule regression. Three separate merges have collapsed these two lines into one, so
# the split is now checked rather than trusted.
corpora-split:
	@bad=$$(for c in $(TS_CORPORA); do case $$c in flask-*|django-*|python-*|aiohttp-*|tornado-*) echo $$c;; esac; done); \
	 bad="$$bad $$(for c in $(PY_CORPORA); do case $$c in express-*|nestjs-*|next-*|electron-*|msw-*) echo $$c;; esac; done)"; \
	 if [ -n "$$(echo $$bad | tr -d ' ')" ]; then echo "corpus in the wrong frontend list: $$bad"; exit 1; fi; \
	 echo "corpora split ok: $(words $(TS_CORPORA)) TypeScript, $(words $(PY_CORPORA)) Python"

bench: corpora-split
	@cd core && go test ./internal/taint/ -run TestCorpusScores -v -count=1 2>&1 | grep -E 'precision|FALSE|DRIFT|FAIL|ok '

# Regenerates every corpus golden IR and copies its expectation manifest next to
# it, so the two can never drift apart.
testdata:
	@for c in $(TS_CORPORA); do \
		node frontends/typescript/src/index.ts testdata/$$c --out $(GOLDEN)/$$c.ir.json; \
		cp testdata/$$c/expected.json $(GOLDEN)/$$c.expected.json; \
		[ -f testdata/$$c/sast-policy.json ] && cp testdata/$$c/sast-policy.json $(GOLDEN)/$$c.policy.json || true; \
	done
	@for c in $(PY_CORPORA); do \
		python3 frontends/python/src/main.py testdata/$$c --out $(GOLDEN)/$$c.ir.json; \
		cp testdata/$$c/expected.json $(GOLDEN)/$$c.expected.json; \
	done

fmt:
	cd core && gofmt -w .

clean:
	rm -f $(IR_TMP) .sast-baseline.json
