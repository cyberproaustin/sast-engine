package taint_test

import (
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/assertion"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/scan"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

func stateOf(rep assertion.Report, id string) assertion.Evaluated {
	for _, e := range rep.Requirements {
		if e.Requirement.ID == id {
			return e
		}
	}
	return assertion.Evaluated{}
}

// The coverage map exists to advertise gaps. A map listing only what the tool can do
// is marketing (ADR-007).
func TestCoverageMapReportsWhatCannotBeChecked(t *testing.T) {
	rep := assertion.Evaluate(runScan(t, "express-idor"))
	counts := rep.Counts()

	if counts[assertion.OutOfReach] == 0 {
		t.Error("requirements static analysis cannot decide must be listed, not omitted")
	}
	// Everything in the catalog is now either asserted or explicitly out of reach, so
	// there is no longer a decidable-but-unbuilt entry to point at. That does not mean
	// the gaps are gone; it means the catalog is a subset of the standard and the gap
	// moved to the catalog's own edge. The map has to say so, because a report showing
	// full coverage of a hand-picked subset is precisely the false completeness this
	// design exists to prevent (ADR-007).
	if counts[assertion.NotBuilt] == 0 && assertion.CatalogScope == "" {
		t.Error("with nothing listed as unbuilt, the map must state that it covers only a subset")
	}
	if !strings.Contains(assertion.CatalogScope, assertion.ASVSEdition) {
		t.Error("the scope statement must name the edition it is a subset of")
	}

	for _, e := range rep.Requirements {
		if e.State == assertion.OutOfReach || e.State == assertion.NotBuilt {
			if e.Reason == "" {
				t.Errorf("%s is uncovered without saying why", e.Requirement.ID)
			}
		}
	}
}

// The failure this whole design exists to avoid: an assertion whose analysis never ran
// must not be reported as satisfied (ADR-003).
func TestUnevaluatedRequirementIsNotSatisfied(t *testing.T) {
	doc := loadCorpusIR(t, "express-idor")

	full := assertion.Evaluate(scan.Run(doc, model.Builtin(), nil))
	if got := stateOf(full, "8.2.2").State; got != assertion.Violated {
		t.Fatalf("premise: V4.2.1 should be violated with full capabilities, got %s", got)
	}

	// Strip control flow. The ownership policy can no longer be evaluated, and the
	// codebase has not changed — so the requirement must not become satisfied.
	doc.Frontend.Capabilities.ControlFlow = false
	stripped := assertion.Evaluate(scan.Run(doc, model.Builtin(), nil))

	got := stateOf(stripped, "8.2.2")
	if got.State == assertion.Satisfied {
		t.Fatal("a requirement whose analysis did not run must never read as satisfied")
	}
	if got.State != assertion.NotEvaluated {
		t.Errorf("want not-evaluated, got %s", got.State)
	}
	if got.Reason == "" {
		t.Error("an unevaluated requirement must say why it could not be judged")
	}
}

// The Top 10 is derived from each finding's CWE on the way out, never authored on a
// rule (ADR-007).
func TestTop10IsDerivedFromCWE(t *testing.T) {
	rep := assertion.Evaluate(runScan(t, "express-idor"))

	if len(rep.Rollup) != 1 {
		t.Fatalf("want one rolled-up category, got %+v", rep.Rollup)
	}
	entry := rep.Rollup[0]
	if entry.Category != assertion.Top10For("CWE-639") {
		t.Errorf("category should come from the CWE mapping, got %q", entry.Category)
	}
	// Three ownership findings plus one unmet access-control expectation; both CWEs
	// belong to the same category, which is the rollup doing its job.
	if entry.Findings != 4 {
		t.Errorf("want 4 findings rolled up, got %d", entry.Findings)
	}

	// One policy, two channels, two weaknesses — and they roll up to different
	// categories. The identity comes from what was reached, not from the judgement.
	inj := assertion.Evaluate(runScan(t, "express-command-injection"))
	byCategory := map[string]int{}
	for _, r := range inj.Rollup {
		byCategory[r.Category] = r.Findings
	}
	// Shell injection and cross-site scripting are different weaknesses that share a
	// rollup category, so the category count cannot separate them and is not what this
	// test is about. What it is about is that a tainted executable PATH lands somewhere
	// else entirely: the identity comes from the channel that was reached, and the Top 10
	// is derived from that rather than authored on the policy (ADR-007).
	if byCategory[assertion.Top10For("CWE-78")] < 2 {
		t.Errorf("want the shell findings under Injection, got %+v", inj.Rollup)
	}
	if assertion.Top10For("CWE-73") == assertion.Top10For("CWE-78") {
		t.Fatal("exec-path and shell should not share a category; the mapping has drifted")
	}
	if byCategory[assertion.Top10For("CWE-73")] != 1 {
		t.Errorf("want 1 exec-path finding under its own category, got %+v", inj.Rollup)
	}
	if assertion.Top10For("CWE-78") == assertion.Top10For("CWE-73") {
		t.Error("these weaknesses belong to different Top 10 categories")
	}
}

// An unmapped CWE is reported as unmapped rather than defaulted into a category.
// Silently defaulting is how a tool implies uniform coverage it does not have.
//
// No corpus produces an unmapped CWE, so this drives the rollup directly. Testing only
// the lookup would leave the defaulting path unguarded — which it was.
func TestUnmappedCWEIsNotGuessedIntoACategory(t *testing.T) {
	if got := assertion.Top10For("CWE-99999"); got != "" {
		t.Errorf("an unknown CWE must not resolve to a category, got %q", got)
	}

	synthetic := scan.Result{
		IR:    loadCorpusIR(t, "express-idor"),
		Taint: taint.Result{Applicable: true, Findings: []taint.Finding{{CWE: "CWE-99999"}}},
	}
	rep := assertion.Evaluate(synthetic)

	if len(rep.Unmapped) != 1 || rep.Unmapped[0] != "CWE-99999" {
		t.Fatalf("an unmapped CWE must be reported as unmapped, got %v", rep.Unmapped)
	}
	for _, r := range rep.Rollup {
		for _, c := range r.CWEs {
			if c == "CWE-99999" {
				t.Errorf("unmapped CWE was folded into %q", r.Category)
			}
		}
	}
}

// Different corpora exercise different requirements; the map is per-run, not static.
func TestCoverageIsPerRun(t *testing.T) {
	injection := assertion.Evaluate(runScan(t, "express-command-injection"))
	leak := assertion.Evaluate(runScan(t, "express-error-leak"))

	if stateOf(injection, "1.2.5").State != assertion.Violated {
		t.Error("the injection corpus should violate the command-injection requirement")
	}
	if stateOf(injection, "16.5.1").State != assertion.Satisfied {
		t.Error("the injection corpus leaks no error detail")
	}
	if stateOf(leak, "16.5.1").State != assertion.Violated {
		t.Error("the error-leak corpus should violate the error-handling requirement")
	}
	if stateOf(leak, "1.2.5").State != assertion.Satisfied {
		t.Error("the error-leak corpus runs no commands")
	}
}
