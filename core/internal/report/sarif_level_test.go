package report

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// A finding's SARIF level must say what the engine believes about it, not how sure the
// analysis was. The two came apart badly in the field: across ten unmodified repositories
// the engine emitted 82 findings at level error whose own gating property was false,
// against 41 that gated. Every consumer of SARIF reads error as "act on this".
func TestLevelReflectsJudgementNotConfidence(t *testing.T) {
	gating := taint.Finding{Confidence: taint.High, EntryAnchored: true}

	for _, c := range []struct {
		name  string
		f     taint.Finding
		level string
		why   string
	}{
		{"anchored and certain", gating, "error",
			"it would fail a build, which is the only thing error should mean"},

		{"high confidence, no entry point", taint.Finding{Confidence: taint.High}, "warning",
			"reaching nothing enumerated is not an assertion over the surface (ADR-009)"},

		{"high confidence, turns on something unseen",
			taint.Finding{Confidence: taint.High, EntryAnchored: true, DependsOnUse: "what the digest is for"},
			"warning", "the engine said itself that it cannot decide this one"},

		{"in a test module",
			taint.Finding{Confidence: taint.High, EntryAnchored: true, InTestModule: true},
			"note", "a credential in a fixture is in the history and is not a production defect"},

		{"test module outranks everything else",
			taint.Finding{Confidence: taint.High, EntryAnchored: true, InTestModule: true, DependsOnUse: "x"},
			"note", "the strongest reason to discount it is the one worth publishing"},

		{"medium confidence", taint.Finding{Confidence: taint.Medium, EntryAnchored: true}, "warning",
			"an inferred expectation never gates (ADR-010)"},
	} {
		if got := levelFor(c.f); got != c.level {
			t.Errorf("%s: level %q, want %q — %s", c.name, got, c.level, c.why)
		}
	}

	// The baseline records a finding; it does not stop it being one (ADR-014). Level is
	// computed from the finding alone, so nothing about a run can quietly downgrade it.
	if levelFor(gating) != "error" {
		t.Error("a gating finding must stay error regardless of any baseline or scope")
	}
}
