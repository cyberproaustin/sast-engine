package ledger_test

import (
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ledger"
)

// The catalog is the denominator every coverage number rests on, so it has to load and it
// has to be the real thing rather than a stub someone left behind.
func TestCatalogLoads(t *testing.T) {
	all := ledger.All()
	if len(all) < 900 {
		t.Fatalf("only %d weaknesses; the embedded catalog is not a full CWE release", len(all))
	}
	if !strings.HasPrefix(ledger.Edition(), "CWE ") {
		t.Errorf("edition %q does not name the catalog release", ledger.Edition())
	}

	// Spot-check against the published catalog rather than against our own claims.
	want := map[string]string{
		"CWE-79": "Cross-site Scripting",
		"CWE-89": "SQL Injection",
		"CWE-22": "Path Traversal",
	}
	seen := map[string]string{}
	for _, e := range all {
		if _, ok := want[e.ID]; ok {
			seen[e.ID] = e.Name
		}
	}
	for id, fragment := range want {
		if name, ok := seen[id]; !ok {
			t.Errorf("%s is missing from the catalog", id)
		} else if !strings.Contains(name, fragment) {
			t.Errorf("%s is named %q, which does not contain %q; the catalog may be wrong", id, name, fragment)
		}
	}
}

// A weakness the engine does not cover, with no stated reason, is indistinguishable from
// one nobody thought about. That distinction is the entire value of holding a ledger
// rather than a list of rules (ADR-007).
func TestEveryClaimStatesItsReason(t *testing.T) {
	for _, e := range ledger.All() {
		if e.Claim.State == ledger.Asserted || e.Claim.State == ledger.Partial {
			if len(e.Claim.By) == 0 {
				t.Errorf("%s is claimed as %s but names nothing that asserts it", e.ID, e.Claim.State)
			}
		}
		if e.Claim.Reason == "" {
			t.Errorf("%s has state %s with no reason", e.ID, e.Claim.State)
		}
	}
}

// Coverage is reported against weaknesses a rule could actually be written for. Counting
// against all 969 would flatter the number by including hardware, process and deprecated
// entries; counting against only what we cover would be meaningless.
func TestCoverageDenominatorIsHonest(t *testing.T) {
	in := ledger.InScope()
	if len(in) < 100 {
		t.Fatalf("only %d in-scope weaknesses; the filter is too aggressive to be believable", len(in))
	}
	for _, e := range in {
		if !e.HasCodeShape() {
			t.Errorf("%s is a %s and has no code shape; it must not be in the denominator", e.ID, e.Abstraction)
		}
		if !e.StaticDetectable {
			t.Errorf("%s has no static detection method and must not be in the denominator", e.ID)
		}
		if e.Status == "Deprecated" {
			t.Errorf("%s is deprecated and must not be in the denominator", e.ID)
		}
	}

	asserted, subsumed, total := ledger.Covered()
	if asserted == 0 || asserted > total {
		t.Errorf("coverage %d/%d is not a sensible fraction", asserted, total)
	}
	if asserted+subsumed > total {
		t.Errorf("asserted %d plus subsumed %d exceeds the denominator %d", asserted, subsumed, total)
	}
}

// A claim that says it covers everything beneath it must itself be a claim the engine
// stands behind. Subsuming from a not-built or undecidable parent would hand a whole
// branch of the catalog a coverage it has no basis for.
func TestSubsumingClaimsAreThemselvesAsserted(t *testing.T) {
	for _, e := range ledger.All() {
		if !e.Claim.Subsumes {
			continue
		}
		if e.Claim.State != ledger.Asserted && e.Claim.State != ledger.Partial {
			t.Errorf("%s subsumes its children while claiming %q", e.ID, e.Claim.State)
		}
		if len(e.Claim.By) == 0 {
			t.Errorf("%s subsumes its children but names no rule that does the catching", e.ID)
		}
	}
}

// Nothing may be subsumed without naming the parent doing the work, for the same reason
// nothing may be unbuilt without a reason: a claim nobody can check is not a claim.
func TestSubsumedEntriesNameTheirParent(t *testing.T) {
	for _, e := range ledger.InScope() {
		if e.Claim.State != ledger.Subsumed {
			continue
		}
		if !strings.Contains(e.Claim.Reason, "CWE-") {
			t.Errorf("%s is subsumed but its reason names no parent: %q", e.ID, e.Claim.Reason)
		}
		if len(e.Claim.By) == 0 {
			t.Errorf("%s is subsumed but names no rule that catches it", e.ID)
		}
	}
}

// Every rule the engine runs must be named by a claim, and every rule a claim names must
// exist. Two real drifts were found by hand before this test existed: CWE-134 had a
// working rule and no claim at all, so the coverage map reported it unbuilt while the
// engine detected it; and CWE-539 named a policy that had been split in two and renamed.
//
// Both failure directions are silent. A rule nobody claims is coverage the report does not
// take credit for; a claim naming nothing is a promise with no code behind it.
func TestClaimsAndRulesNameEachOther(t *testing.T) {
	m := model.Builtin()

	// The convention analysis is named by its kind rather than by a rule id, because it
	// has no per-weakness rules: it compares an entry point against its peers.
	known := map[string]bool{"expectations": true}
	for _, p := range m.Policies {
		known[p.ID] = true
	}
	for _, s := range m.CallShapes {
		known[s.ID] = true
	}
	for _, d := range m.Decisions {
		known[d.ID] = true
	}

	claimed := map[string]bool{}
	for _, e := range ledger.All() {
		for _, by := range e.Claim.By {
			claimed[by] = true
			if !known[by] {
				t.Errorf("%s claims to be backed by %q, which no rule in the model defines", e.ID, by)
			}
		}
	}

	for id := range known {
		if id == "expectations" {
			continue
		}
		if !claimed[id] {
			t.Errorf("rule %q runs but no claim names it, so the coverage map takes no credit for it", id)
		}
	}
}
