TS_CORPORA := express-command-injection express-session-fixation express-csrf written-secrets express-error-in-page express-export-table express-dev-error-handler express-symbol-coverage express-redos express-reassigned express-rejection-continues express-async clean-express express-authz express-error-leak express-webhook-leak express-idor express-real-shapes nestjs-controller unanchored-decorator nestjs-ownership nestjs-unresolved-input express-code-interpreter express-sql-injection express-xss nestjs-destructured-params weak-crypto express-path-traversal express-ssrf express-redirect-deserialize express-cipher-regex hardcoded-secret express-upload-type express-cookie-attributes express-misconfiguration express-template-injection express-factory-handler express-xxe express-mass-assignment express-weak-kdf express-dynamic-load express-environment-exposure express-credential-logging express-secrets-and-randomness express-tls-downgrade express-cookie-storage express-credential-in-url express-header-injection express-guessable-token express-trusted-claim express-trusted-origin express-trust-boundary express-resource-and-path express-unsalted-hash express-observable-values express-session-lifetime express-supply-chain express-password-policy express-personal-data electron-window express-radix express-shared-state express-timing express-bind-address express-reused-iv express-origin-check express-session-store express-nosql-where express-template-xss express-template-engines next-pages-router reassignment-kills-taint regex-complexity unowned-record-access
PY_CORPORA := tornado-urlspec django-urlconf flask-command-injection flask-container-update flask-sql-injection flask-class-views python-tls-verification flask-upload-type flask-cookie-attributes flask-misconfiguration flask-template-injection flask-value-defaults flask-xxe flask-unsafe-files flask-csv-injection flask-secrets-and-randomness flask-query-languages flask-search-path flask-password-storage flask-unsalted-hash flask-observable-values flask-session-lifetime flask-entity-expansion flask-password-policy flask-personal-data python-comparison flask-shared-state flask-timing flask-bind-address flask-archive-extract flask-template-xss flask-config-secrets flask-code-execution flask-symbol-coverage aiohttp-routes flask-pattern-and-xml weak-hash-by-use
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

bench:
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
