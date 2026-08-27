package taint_test

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// Gating is a strict subset of reported, and this is what keeps it one.
//
// The three context terms were written out inside Actionable before they had a name, and
// the report and the score each asked them again in their own words. That is how a
// hardcoded key in a spec file came to be excluded in one place and counted in another.
// The terms live in policy.Context now; this asserts the containment that made moving
// them safe, so a later edit to either side cannot quietly separate "we would fail a
// build on this" from "we would tell a maintainer about this".
func TestNothingGatesThatIsNotReported(t *testing.T) {
	base := taint.Finding{Confidence: taint.High, EntryAnchored: true}

	for _, c := range []struct {
		name string
		f    taint.Finding
	}{
		{"a key in a test module", func() taint.Finding { f := base; f.InTestModule = true; return f }()},
		{"a weakness in vendored code", func() taint.Finding { f := base; f.Provenance = ir.Vendored; return f }()},
		{"an argument an operator typed", func() taint.Finding { f := base; f.EntryTrust = ir.Operator; return f }()},
		{"a timer nothing outside the process reaches", func() taint.Finding { f := base; f.EntryTrust = ir.Internal; return f }()},
	} {
		if c.f.Reportable() {
			t.Errorf("%s: reportable, want enumerated only", c.name)
		}
		if c.f.Actionable() {
			t.Errorf("%s: would gate a build while not being reported at all", c.name)
		}
		if c.f.NotReportedBecause() == "" {
			t.Errorf("%s: kept out of the reported set without saying why", c.name)
		}
	}

	// The other direction, so this cannot be satisfied by refusing everything: the
	// finding that IS the engine's claim about somebody's application.
	if !base.Reportable() || !base.Actionable() {
		t.Error("an anchored, certain finding on application code must be both")
	}
	// And reportable is deliberately weaker than gating. How well the call graph
	// resolved (ADR-005) is a different question from whose application this is.
	medium := base
	medium.Confidence = taint.Medium
	if !medium.Reportable() || medium.Actionable() {
		t.Error("a medium-confidence finding on a live route is reported and does not gate")
	}
}
