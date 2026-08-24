package taint_test

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/scan"
)

func ownershipOn(res scan.Result) []string {
	var out []string
	for _, f := range res.Taint.Findings {
		if f.Analysis == "unowned-record-access" {
			out = append(out, f.EntryPoint)
		}
	}
	return out
}

// Registration must look up a record by caller-supplied input before any actor
// exists. That is not an ownership failure — but code cannot tell it apart from an
// unauthenticated data endpoint, so the team declares it (ADR-011).
func TestDeclaredIdentityEndpointIsExemptFromOwnership(t *testing.T) {
	declared := runScan(t, "express-idor")
	for _, entry := range ownershipOn(declared) {
		if entry == "POST /api/auth/register [express]" {
			t.Error("a declared identity-establishing endpoint must not require an owner")
		}
	}

	// Without the declaration the same code is reported. The exemption comes from
	// what the team stated, never from the engine guessing.
	undeclared := scan.Run(loadCorpusIR(t, "express-idor"), model.Builtin(), nil)
	var found bool
	for _, entry := range ownershipOn(undeclared) {
		if entry == "POST /api/auth/register [express]" {
			found = true
		}
	}
	if !found {
		t.Error("undeclared, the same endpoint must still be judged")
	}
}

// A declaration's effect is always visible, with the property and the stated reason.
func TestExemptionIsReportedNotSilent(t *testing.T) {
	res := runScan(t, "express-idor")

	if len(res.Exempted) != 1 {
		t.Fatalf("want 1 recorded exemption, got %d", len(res.Exempted))
	}
	e := res.Exempted[0]
	if e.Property != "establishesIdentity" {
		t.Errorf("want the property named, got %q", e.Property)
	}
	if e.PolicyID != "unowned-record-access" {
		t.Errorf("want the exempted judgement named, got %q", e.PolicyID)
	}
	if e.Reason == "" || e.DeclaredBy == "" {
		t.Errorf("an exemption must carry its declaration and reason: %+v", e)
	}
}

// The exemption is scoped to the judgement the policy names. It must not silence
// unrelated findings on the same entry point, or anything on other entry points.
func TestExemptionIsScopedToItsJudgement(t *testing.T) {
	res := runScan(t, "express-idor")

	entries := ownershipOn(res)
	if len(entries) != 3 {
		t.Fatalf("the other ownership findings must survive, got %v", entries)
	}
	for _, want := range []string{
		"GET /api/orders/:id [express]",
		"DELETE /api/orders/:id [express]",
		"GET /api/orders/:id/audited [express]",
	} {
		var seen bool
		for _, e := range entries {
			if e == want {
				seen = true
			}
		}
		if !seen {
			t.Errorf("%s should still be reported", want)
		}
	}
}
