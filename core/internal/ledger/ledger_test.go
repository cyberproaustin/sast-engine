package ledger_test

import (
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

	asserted, total := ledger.Covered()
	if asserted == 0 || asserted > total {
		t.Errorf("coverage %d/%d is not a sensible fraction", asserted, total)
	}
}
