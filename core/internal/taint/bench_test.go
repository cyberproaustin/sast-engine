package taint_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/bench"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/scan"
)

// Corpora are regenerated with `make testdata`. Adding a corpus here is how a new
// capability gets a permanent regression check.
var corpora = []string{
	"absent-security-option",
	"anchored-regex-guard",
	"registered-destination",
	"app-router-pages",
	"express-command-injection",
	"one-weakness-per-site",
	"express-async",
	"clean-express",
	"express-authz",
	"express-error-leak",
	"error-detail-audience",
	"express-webhook-leak",
	"express-idor",
	"express-real-shapes",
	"nestjs-controller",
	"unanchored-decorator",
	"nestjs-ownership",
	"nestjs-unresolved-input",
	"express-code-interpreter",
	"express-sql-injection",
	"express-xss",
	"nestjs-destructured-params",
	"weak-crypto",
	"express-path-traversal",
	"express-ssrf",
	"express-redirect-deserialize",
	"express-cipher-regex",
	"hardcoded-secret",
	"flask-command-injection",
	"flask-container-update",
	"django-update-shape",
	"flask-sql-injection",
	"flask-class-views",
	"python-tls-verification",
	"express-upload-type",
	"flask-upload-type",
	"express-cookie-attributes",
	"flask-cookie-attributes",
	"express-misconfiguration",
	"flask-misconfiguration",
	"express-template-injection",
	"flask-template-injection",
	"express-factory-handler",
	"flask-value-defaults",
	"express-xxe",
	"express-mass-assignment",
	"express-weak-kdf",
	"express-dynamic-load",
	"express-environment-exposure",
	"express-credential-logging",
	"express-secrets-and-randomness",
	"flask-secrets-and-randomness",
	"flask-query-languages",
	"express-tls-downgrade",
	"express-cookie-storage",
	"express-credential-in-url",
	"express-header-injection",
	"express-guessable-token",
	"express-trusted-claim",
	"express-trusted-origin",
	"express-trust-boundary",
	"flask-archive-extract",
	"express-template-xss",
	"express-template-engines",
	"flask-template-xss",
	"flask-config-secrets",
	"flask-code-execution",
	"flask-symbol-coverage",
	"aiohttp-routes",
	"flask-pattern-and-xml",
	"express-session-fixation",
	"express-csrf",
	"written-secrets",
	"express-error-in-page",
	"express-export-table",
	"express-dev-error-handler",
	"express-symbol-coverage",
	"express-redos",
	"express-reassigned",
	"express-rejection-continues",
	"express-session-store",
	"express-nosql-where",
	"express-origin-check",
	"express-reused-iv",
	"express-bind-address",
	"flask-bind-address",
	"express-timing",
	"flask-timing",
	"express-shared-state",
	"flask-shared-state",
	"express-radix",
	"python-comparison",
	"electron-window",
	"enclosing-config-guard",
	"express-personal-data",
	"flask-personal-data",
	"express-password-policy",
	"flask-password-policy",
	"express-supply-chain",
	"flask-entity-expansion",
	"express-session-lifetime",
	"flask-session-lifetime",
	"express-observable-values",
	"flask-observable-values",
	"express-unsalted-hash",
	"flask-unsalted-hash",
	"express-resource-and-path",
	"flask-password-storage",
	"flask-search-path",
	"flask-xxe",
	"flask-unsafe-files",
	"flask-csv-injection",
	"django-urlconf",
	"django-dotted-include",
	"django-package-reexport",
	"django-aliased-urlconf",
	"django-ambiguous-include",
	"django-keyword-registration",
	"django-session-identity-change",
	"django-declared-authorization",
	"next-pages-router",
	"tsconfig-path-alias",
	"workspace-package-name",
	"tornado-urlspec",
	"graphene-schema",
	"trpc-router",
	"reassignment-kills-taint",
	"weak-hash-by-use",
	"client-identifier",
	"credential-literal-tested",
	"keyword-argument-binding",
	"sibling-guard-differential",
	"express-control-coverage",
	"stored-read-invariant",
	"regex-complexity",
	"unowned-record-access",
	"unbounded-resource",
	"unbounded-input-read",
	"express-route-metadata",
	"flask-route-metadata",
	"second-order-taint",
	"non-first-party-code",
	"scheduled-jobs",
	"management-command",
	"process-start",
	"try-return-not-caught",
	"msw-not-express",
	"cipher-mode-decides-the-iv",
	"decipher-update",
	"literal-return-summary",
	"unreferenced-component",
	"python-inherited-method",
	"argument-injection-into-argv",
	"rate-limit-key",
	"rate-limit-scope",
	"secret-identifier-role",
	"python-try-except",
	"fastify-routes",
	"described-route-paths",
	"forwarded-registrar",
	"route-registry-loop",
	"static-plugin-mount",
	"flask-url-rule-alias",
	"secret-file-created-before-chmod",
	"non-constant-time-secret-comparison",
	"membership-test-not-a-comparison",
	"mounted-auth-comparison",
	"regex-capture-arity-not-checked",
	"response-context",
	"url-context",
	"template-context-elsewhere",
	"promise-resolution",
	"absent-dependency",
	"upstream-response",
	"return-to-the-calling-site",
	"claim-enclosed-in-an-object",
	"digest-compared-against-what",
	"identity-is-not-a-resource",
	"swapped-accessor",
	"flask-swapped-accessor",
	"drf-action-routes",
	"route-parameter-source",
	"reference-resolution",
	"local-route-destination",
	"type-brand-not-credential",
	"secret-key-identifier",
	"rate-limit-key-header",
	"settings-module-secret",
	"django-manager-lookup",
	"destructured-parameter",
	"credential-instead-of-session",
	"python-receiver-binding",
	"python-call-under-attribute",
	"django-int-capture",
	"presence-guarded-verification",
	"credential-not-reissued",
	"graphene-undeclared-permission",
	"permission-looked-up-and-dropped",
	"django-csrf-state-change",
	"cross-host-credential-forwarding",
	"django-app-config-urls",
	"django-model-view-registry",
	"django-instance-request",
}

func scoreCorpus(t *testing.T, name string) bench.Report {
	t.Helper()

	c, err := bench.LoadCorpus("testdata/" + name + ".expected.json")
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	f, err := os.Open("testdata/" + name + ".ir.json")
	if err != nil {
		t.Fatalf("open corpus IR: %v", err)
	}
	defer f.Close()

	doc, err := ir.Load(f)
	if err != nil {
		t.Fatalf("load corpus IR: %v", err)
	}

	// Score what the tool actually reports for this corpus, declarations included:
	// a corpus's policy is part of the corpus.
	return bench.Score(c, scan.Run(doc, model.Builtin(), loadPolicy(t, name)).Taint)
}

// The whole suite, scored. Precision and recall are asserted per corpus so a
// regression in either direction fails the build.
func TestCorpusScores(t *testing.T) {
	for _, name := range corpora {
		t.Run(name, func(t *testing.T) {
			rep := scoreCorpus(t, name)
			t.Log(rep.Summary())

			for _, fp := range rep.FalsePositives {
				t.Errorf("FALSE POSITIVE: %s at %s from %s\n  path: %d hops",
					fp.CWE, fp.SinkLoc, fp.SourceLabel, len(fp.Path))
			}
			for _, fn := range rep.FalseNegatives {
				t.Errorf("FALSE NEGATIVE: %s (%s)", fn, fn.Note)
			}
			for _, m := range rep.WrongConfidence {
				t.Errorf("CONFIDENCE DRIFT: %s expected %s, got %s",
					m.Expectation, m.Expectation.Confidence, m.Got)
			}
			// Not failures. A corpus is free to assert a weakness in a fixture or behind
			// a management command, and several do on purpose -- the whole point of the
			// non-HTTP entry-point corpora is that the engine finds those. What this says
			// is that the finding is enumerated and not reported, so a reader comparing
			// this line to a repository's finding count knows which set each number is.
			for _, e := range rep.ExpectedButNotReported {
				t.Logf("ENUMERATED, NOT REPORTED: %s", e)
			}
			for _, f := range rep.EnumeratedOnly {
				t.Logf("ENUMERATED, NOT REPORTED, NOT EXPECTED: %s at %s from %s (%s)",
					f.CWE, f.SinkLoc, f.SourceLabel, f.NotReportedBecause())
			}
		})
	}
}

// The false-positive corpus is the denominator for every precision claim. It is
// asserted separately because "produces nothing on safe code" is a distinct
// property from "finds things in vulnerable code", and it is the one that decides
// whether anyone leaves the tool switched on.
func TestCleanCorpusProducesNothing(t *testing.T) {
	rep := scoreCorpus(t, "clean-express")

	if rep.NotApplicable {
		t.Fatal("clean corpus did not run; an unrun analysis is not a clean result")
	}
	// Both sets, because precision is now scored over the reported one. A claim the
	// engine merely enumerates is still a claim about safe code, and letting the
	// context judgement absorb one here would make this measurement say less than it
	// did before the judgement existed.
	if len(rep.FalsePositives)+len(rep.EnumeratedOnly) != 0 {
		for _, fp := range rep.FalsePositives {
			t.Errorf("false positive on safe code: %s at %s from %s",
				fp.CWE, fp.SinkLoc, fp.SourceLabel)
		}
		for _, fp := range rep.EnumeratedOnly {
			t.Errorf("enumerated on safe code: %s at %s from %s (%s)",
				fp.CWE, fp.SinkLoc, fp.SourceLabel, fp.NotReportedBecause())
		}
		t.Fatalf("precision %.2f on the clean corpus", rep.Precision())
	}
}

func TestEnclosingConfigurationGuardExplainsRatherThanSilences(t *testing.T) {
	f, err := os.Open("testdata/enclosing-config-guard.ir.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc, err := ir.Load(f)
	if err != nil {
		t.Fatal(err)
	}

	findings := scan.Run(doc, model.Builtin(), loadPolicy(t, "enclosing-config-guard")).Taint.Findings
	var guarded, unguarded string
	for _, finding := range findings {
		switch finding.SinkLoc.Line {
		case 9:
			guarded = finding.DependsOnUse
		case 13:
			unguarded = finding.DependsOnUse
		}
	}
	if !strings.Contains(guarded, "env.NODE_ENV") || !strings.Contains(guarded, "unset or mis-set") {
		t.Fatalf("guarded finding did not name its deployment dependency: %q", guarded)
	}
	if unguarded != "" {
		t.Fatalf("unguarded finding was demoted: %q", unguarded)
	}
}

// Higher-order and async flow: these are the boundaries a first-order engine loses,
// and they are most of what Node code is made of.
func TestAsyncAndHigherOrderFlowsAreFound(t *testing.T) {
	rep := scoreCorpus(t, "express-async")

	if rep.Recall() != 1 {
		t.Errorf("recall %.2f on async corpus; missed: %v", rep.Recall(), rep.FalseNegatives)
	}
	if rep.TruePositives != 3 {
		t.Errorf("want 3 true positives (await, .then continuation, forEach callback), got %d", rep.TruePositives)
	}
}

// TestEveryLoweredCorpusIsScored closes the gap between having a fixture and running one.
//
// A corpus lives in three places -- a directory of source, an entry in the Makefile that
// lowers it, and a name in the list above that scores it -- and forgetting the third
// leaves a fixture that is regenerated on every build and never checked. Nothing about
// that failure is visible: the suite passes, the coverage looks the same, and the rule the
// fixture was written to hold has no test.
func TestEveryLoweredCorpusIsScored(t *testing.T) {
	golden, err := filepath.Glob(filepath.Join("testdata", "*.ir.json"))
	if err != nil {
		t.Fatal(err)
	}
	scored := make(map[string]bool, len(corpora))
	for _, c := range corpora {
		scored[c] = true
	}
	for _, g := range golden {
		name := strings.TrimSuffix(filepath.Base(g), ".ir.json")
		if !scored[name] {
			t.Errorf("corpus %q is lowered but never scored; add it to the list in this file", name)
		}
	}
}
