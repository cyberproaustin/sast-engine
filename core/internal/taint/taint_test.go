package taint_test

import (
	"os"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// The golden IR is produced by the TypeScript frontend from
// testdata/express-command-injection. Regenerate with `make testdata`.
const goldenIR = "testdata/express-command-injection.ir.json"

func loadGolden(t *testing.T) *ir.IR {
	t.Helper()
	f, err := os.Open(goldenIR)
	if err != nil {
		t.Fatalf("open golden IR: %v", err)
	}
	defer f.Close()

	doc, err := ir.Load(f)
	if err != nil {
		t.Fatalf("load golden IR: %v", err)
	}
	return doc
}

// findBySourceAndChannel picks the one finding from this source that reached this kind
// of destination. Selecting on both is what keeps these tests meaningful as the model
// grows: the same untrusted value legitimately reaches a shell and an HTML response,
// and each is a different judgement about a different destination.
func findBySourceAndChannel(t *testing.T, findings []taint.Finding, source, channel string) taint.Finding {
	t.Helper()
	for _, f := range findings {
		if f.SourceLabel == source && f.ChannelID == channel {
			return f
		}
	}
	t.Fatalf("no finding from %q reaching a %s channel; got %d findings", source, channel, len(findings))
	return taint.Finding{}
}

// The whole point of the skeleton: taint that crosses a function boundary AND a
// module boundary is still found. A single-function analysis cannot do this.
func TestInterproceduralCrossModuleFlowIsFound(t *testing.T) {
	res := taint.Analyze(loadGolden(t), model.Builtin())

	if !res.Applicable {
		t.Fatalf("analysis reported not applicable, missing: %v", res.MissingCapabilities)
	}
	// Two shell injections, one tainted executable path, and three reflections of the
	// same values into a text/html response body. Asserted by channel rather than by
	// count: one source reaching several sinks is the normal case, and a test that
	// pins the total has to be edited every time the model learns a new destination
	// without ever having checked the thing it was written to check.
	f := findBySourceAndChannel(t, res.Findings, "req.query.host", "shell-command")
	if f.CWE != "CWE-78" {
		t.Errorf("want CWE-78, got %s", f.CWE)
	}
	if f.SinkSymbol != "child_process.exec" {
		t.Errorf("want sink child_process.exec, got %s", f.SinkSymbol)
	}
	if f.SinkLoc.File != "exec-helper.ts" {
		t.Errorf("sink should be in the helper module, got %s", f.SinkLoc.File)
	}
	if f.SourceLoc.File != "app.ts" {
		t.Errorf("source should be in the route module, got %s", f.SourceLoc.File)
	}
	if f.EntryPoint != "GET /ping [express]" {
		t.Errorf("want entry point GET /ping [express], got %q", f.EntryPoint)
	}
	if f.Confidence != taint.High {
		t.Errorf("fully resolved path should be high confidence, got %s", f.Confidence)
	}
	if !f.Confidence.Gating() {
		t.Error("a high-confidence finding must gate")
	}
}

// Every finding carries the path that justifies it (ADR-006).
func TestFindingCarriesItsEvidence(t *testing.T) {
	res := taint.Analyze(loadGolden(t), model.Builtin())
	f := findBySourceAndChannel(t, res.Findings, "req.query.host", "shell-command")

	if len(f.Path) < 4 {
		t.Fatalf("evidence path too short to be a real justification: %d hops", len(f.Path))
	}
	first, last := f.Path[0], f.Path[len(f.Path)-1]
	if first.Loc.File != "app.ts" {
		t.Errorf("path should start at the source, got %s", first.Loc)
	}
	if last.Loc.File != "exec-helper.ts" {
		t.Errorf("path should end at the sink, got %s", last.Loc)
	}
	for i, h := range f.Path {
		if h.Description == "" {
			t.Errorf("hop %d has no description; an unexplainable hop is not evidence", i)
		}
	}
}

// A sanitizer only clears taint for the context it actually protects (ADR-006).
// encodeURIComponent is a URL encoder and does nothing for a shell sink.
func TestWrongContextSanitizerDoesNotClearTaint(t *testing.T) {
	res := taint.Analyze(loadGolden(t), model.Builtin())
	f := findBySourceAndChannel(t, res.Findings, "req.query.domain", "shell-command")

	if len(f.Sanitizers) != 1 {
		t.Fatalf("want 1 sanitizer recorded, got %d", len(f.Sanitizers))
	}
	s := f.Sanitizers[0]
	if s.Symbol != "encodeURIComponent" {
		t.Errorf("want encodeURIComponent, got %s", s.Symbol)
	}
	if s.Clears {
		t.Error("a URL encoder must not clear taint for a shell sink")
	}
	if s.Required != "shell" {
		t.Errorf("want required context shell, got %q", s.Required)
	}
}

// Precision, not just recall: execFile does not spawn a shell, so a tainted argument
// ARRAY is not command injection. A tainted executable PATH is a different weakness
// and is reported — under CWE-73, not CWE-78.
func TestExecFileDistinguishesArgArrayFromExecutablePath(t *testing.T) {
	res := taint.Analyze(loadGolden(t), model.Builtin())

	for _, f := range res.Findings {
		if f.EntryPoint == "GET /ping-safe [express]" {
			t.Errorf("a tainted argument array to execFile is not injection: %+v", f)
		}
	}

	var path *taint.Finding
	for i, f := range res.Findings {
		if f.SinkSymbol == "child_process.execFile" {
			path = &res.Findings[i]
		}
	}
	if path == nil {
		t.Fatal("a tainted executable path must be reported")
	}
	if path.CWE != "CWE-73" {
		t.Errorf("a tainted executable path is CWE-73, not %s", path.CWE)
	}
	if path.EntryPoint != "GET /run [express]" {
		t.Errorf("wrong entry point: %s", path.EntryPoint)
	}
}

// An analysis whose capability requirements are unmet reports NOT APPLICABLE and
// produces no findings — which must never be read as a clean result (ADR-003).
func TestUnmetCapabilityIsNotApplicableNotClean(t *testing.T) {
	doc := loadGolden(t)
	doc.Frontend.Capabilities.Interprocedural = false

	res := taint.Analyze(doc, model.Builtin())

	if res.Applicable {
		t.Fatal("analysis requiring interprocedural resolution ran without it")
	}
	if len(res.Findings) != 0 {
		t.Errorf("a not-applicable analysis must not produce findings, got %d", len(res.Findings))
	}
	if len(res.MissingCapabilities) != 1 || res.MissingCapabilities[0] != "interprocedural" {
		t.Errorf("want missing=[interprocedural], got %v", res.MissingCapabilities)
	}
}

func findBySource(t *testing.T, findings []taint.Finding, label string) taint.Finding {
	t.Helper()
	for _, f := range findings {
		if f.SourceLabel == label {
			return f
		}
	}
	t.Fatalf("no finding sourced from %s", label)
	return taint.Finding{}
}
