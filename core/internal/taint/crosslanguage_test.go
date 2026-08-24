package taint_test

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// ADR-008's test, made executable: does the abstraction survive a second language?
//
// The Flask corpus is found by policies written against Express corpora. Nothing about
// the judgement changed — only a classification rule for a request object that is a
// module global rather than a handler parameter, and descriptions of two Python
// channels.
func TestSamePoliciesFindTheSameDefectsInPython(t *testing.T) {
	ts := runScan(t, "express-command-injection")
	py := runScan(t, "flask-command-injection")

	tsInjection := findingsFor(ts.Taint.Findings, "untrusted-input")
	pyInjection := findingsFor(py.Taint.Findings, "untrusted-input")
	if len(tsInjection) == 0 || len(pyInjection) == 0 {
		t.Fatalf("want injection findings in both languages, got %d and %d",
			len(tsInjection), len(pyInjection))
	}
	if tsInjection[0].Analysis != pyInjection[0].Analysis {
		t.Errorf("both languages should violate the same policy; got %q and %q",
			tsInjection[0].Analysis, pyInjection[0].Analysis)
	}

	leak := runScan(t, "express-error-leak")
	tsLeak := findingsFor(leak.Taint.Findings, "internal-error")
	pyLeak := findingsFor(py.Taint.Findings, "internal-error")
	if len(tsLeak) == 0 || len(pyLeak) == 0 {
		t.Fatalf("want exposure findings in both languages, got %d and %d",
			len(tsLeak), len(pyLeak))
	}
	if tsLeak[0].Analysis != pyLeak[0].Analysis {
		t.Errorf("exposure judgement should be language-neutral; got %q and %q",
			tsLeak[0].Analysis, pyLeak[0].Analysis)
	}
}

// The Python frontend has no type inference, and that difference must show up as
// lower confidence rather than as a missing finding (ADR-003, ADR-005). Silence would
// be indistinguishable from safety; a low-confidence finding is not.
func TestWeakerFrontendLosesConfidenceNotFindings(t *testing.T) {
	py := runScan(t, "flask-command-injection")

	injection := findingsFor(py.Taint.Findings, "untrusted-input")
	if len(injection) != 1 {
		t.Fatalf("want the injection reported despite weaker resolution, got %d", len(injection))
	}
	if injection[0].Confidence == taint.High {
		t.Error("a path crossing an unresolved dispatch must not be high confidence")
	}
	if injection[0].Confidence.Gating() {
		t.Error("an unresolved path must not gate a build")
	}

	// Cross-module dataflow still works without a type checker.
	if injection[0].SinkLoc.File != "helpers.py" || injection[0].SourceLoc.File != "app.py" {
		t.Errorf("expected a cross-module flow, got %s -> %s",
			injection[0].SourceLoc.File, injection[0].SinkLoc.File)
	}
}

// A request object is a handler parameter in Express and a module global in Flask.
// That is plumbing, not judgement, and both must classify as the same data.
func TestRequestObjectShapeDoesNotChangeTheClass(t *testing.T) {
	ts := findingsFor(runScan(t, "express-command-injection").Taint.Findings, "untrusted-input")
	py := findingsFor(runScan(t, "flask-command-injection").Taint.Findings, "untrusted-input")

	if len(ts) == 0 || len(py) == 0 {
		t.Fatal("need findings in both languages")
	}
	if ts[0].DataClass != py[0].DataClass {
		t.Errorf("same class expected, got %q and %q", ts[0].DataClass, py[0].DataClass)
	}
	if ts[0].SourceLabel == py[0].SourceLabel {
		t.Errorf("the plumbing genuinely differs; both were %q", ts[0].SourceLabel)
	}
}
