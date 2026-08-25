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
	"express-command-injection",
	"express-async",
	"clean-express",
	"express-authz",
	"express-error-leak",
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
	"express-session-fixation",
	"express-csrf",
	"written-secrets",
	"express-error-in-page",
	"express-export-table",
	"express-dev-error-handler",
	"express-symbol-coverage",
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
	if len(rep.FalsePositives) != 0 {
		for _, fp := range rep.FalsePositives {
			t.Errorf("false positive on safe code: %s at %s from %s",
				fp.CWE, fp.SinkLoc, fp.SourceLabel)
		}
		t.Fatalf("precision %.2f on the clean corpus", rep.Precision())
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
