package report

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
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

		{"vendored module",
			taint.Finding{Confidence: taint.High, EntryAnchored: true, Provenance: ir.Vendored},
			"note", "a true weakness in an upstream copy is worth listing below application code"},

		{"generated module",
			taint.Finding{Confidence: taint.High, EntryAnchored: true, Provenance: ir.Generated},
			"note", "a generated table remains a fact without ranking as hand-written code"},

		{"medium confidence", taint.Finding{Confidence: taint.Medium, EntryAnchored: true}, "warning",
			"an inferred expectation never gates (ADR-010)"},

		// A disclosure is the one judgement whose weight IS its audience. Nine of
		// linkwarden's twenty-one findings were CWE-209 returned to a caller who already
		// holds the account; eight were adjudicated true and none was worth reporting,
		// while the same rule found two of the batch's four worth-reporting findings in
		// uptime-kuma, where the endpoints answer anybody. One rank for both is what
		// teaches a reader to skip the rule.
		{"disclosure to a caller who authenticated",
			taint.Finding{Confidence: taint.High, EntryAnchored: true, AudienceDecides: true, EntryAuthenticates: true},
			"note", "the message reached somebody who is already inside"},

		{"disclosure to anybody at all",
			taint.Finding{Confidence: taint.High, EntryAnchored: true, AudienceDecides: true},
			"error", "no control asks who the caller is, so it describes the system to whoever asked"},

		// Both halves are required, and this is the half that keeps the rank honest: an
		// injection behind a login is the same injection, because what an attacker can do
		// to the system does not change with who they are.
		{"authenticated, but the judgement is not about who receives it",
			taint.Finding{Confidence: taint.High, EntryAnchored: true, EntryAuthenticates: true},
			"error", "only a disclosure is ranked by its audience"},
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
