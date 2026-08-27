TS_CORPORA := absent-dependency anchored-regex-guard cipher-mode-decides-the-iv clean-express described-route-paths electron-window express-async express-authz express-bind-address express-cipher-regex express-code-interpreter express-command-injection express-cookie-attributes express-cookie-storage express-credential-in-url express-credential-logging express-csrf express-dev-error-handler express-dynamic-load express-environment-exposure express-error-in-page express-error-leak express-export-table express-factory-handler express-guessable-token express-header-injection express-idor express-mass-assignment express-misconfiguration express-nosql-where express-observable-values express-origin-check express-password-policy express-path-traversal express-personal-data express-radix express-real-shapes express-reassigned express-redirect-deserialize express-redos express-rejection-continues express-resource-and-path express-reused-iv express-route-metadata express-secrets-and-randomness express-session-fixation express-session-lifetime express-session-store express-shared-state express-sql-injection express-ssrf express-supply-chain express-symbol-coverage express-template-engines express-template-injection express-template-xss express-timing express-tls-downgrade express-trust-boundary express-trusted-claim express-trusted-origin express-unsalted-hash express-upload-type express-weak-kdf express-webhook-leak express-xss express-xxe fastify-routes forwarded-registrar hardcoded-secret literal-return-summary msw-not-express nestjs-controller nestjs-destructured-params nestjs-ownership nestjs-unresolved-input next-pages-router non-first-party-code one-weakness-per-site promise-resolution rate-limit-key reassignment-kills-taint regex-complexity route-registry-loop scheduled-jobs second-order-taint sibling-guard-differential try-return-not-caught tsconfig-path-alias unanchored-decorator unbounded-resource unowned-record-access unreferenced-component weak-crypto written-secrets
PY_CORPORA := aiohttp-routes argument-injection-into-argv client-identifier django-urlconf flask-archive-extract flask-bind-address flask-class-views flask-code-execution flask-command-injection flask-config-secrets flask-container-update flask-cookie-attributes flask-csv-injection flask-entity-expansion flask-misconfiguration flask-observable-values flask-password-policy flask-password-storage flask-pattern-and-xml flask-personal-data flask-query-languages flask-route-metadata flask-search-path flask-secrets-and-randomness flask-session-lifetime flask-shared-state flask-sql-injection flask-symbol-coverage flask-template-injection flask-template-xss flask-timing flask-unsafe-files flask-unsalted-hash flask-upload-type flask-url-rule-alias flask-value-defaults flask-xxe management-command process-start python-comparison python-inherited-method python-tls-verification python-try-except rate-limit-scope tornado-urlspec upstream-response weak-hash-by-use
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
	python3 loop/bin/test_adjudicate.py

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
