package taint_test

import (
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// The judgement is relational, not a pattern: a caller-supplied identifier selects a
// record and the handler never relates it to the caller's identity.
func TestUnownedRecordAccessIsFound(t *testing.T) {
	res := runScan(t, "express-idor")

	var found []string
	for _, f := range res.Taint.Findings {
		if f.Analysis == "unowned-record-access" {
			found = append(found, f.EntryPoint)
		}
	}
	// Two handlers with no check at all, plus one whose check decides nothing.
	if len(found) != 3 {
		t.Fatalf("want 3 unowned-access findings, got %d: %v", len(found), found)
	}
}

// One policy, two operations. Nothing in it mentions reading or deleting — those are
// channel descriptions, and the judgement is about record selection.
func TestOnePolicyCoversReadAndDelete(t *testing.T) {
	res := runScan(t, "express-idor")

	kinds := map[string]bool{}
	for _, f := range res.Taint.Findings {
		if f.Analysis == "unowned-record-access" {
			kinds[f.SinkSymbol] = true
		}
	}
	if len(kinds) != 2 {
		t.Fatalf("want the same policy on two different operations, got %v", kinds)
	}
}

// A handler that compares the record's owner against the caller has done the check.
// The engine must not care how the comparison is spelled.
func TestComparisonAgainstActorIdentitySatisfiesThePolicy(t *testing.T) {
	res := runScan(t, "express-idor")
	for _, f := range res.Taint.Findings {
		if f.Analysis != "unowned-record-access" {
			continue
		}
		if f.EntryPoint == "GET /api/orders/:id/detail [express]" {
			t.Errorf("handler compares order.userId against req.user.id: %+v", f)
		}
	}
}

// Scoping a query by the caller's identity is not record selection by the caller.
func TestQueryScopedByActorIsNotFlagged(t *testing.T) {
	res := runScan(t, "express-idor")
	for _, f := range res.Taint.Findings {
		if f.EntryPoint == "GET /api/orders [express]" {
			t.Errorf("query scoped by req.user.id must not be flagged: %+v", f)
		}
	}
}

// Authentication is not authorization. Every route here applies requireAuth, so a
// tool that treats an auth middleware as sufficient finds nothing.
func TestAuthenticationDoesNotSatisfyOwnership(t *testing.T) {
	res := runScan(t, "express-idor")

	// The order routes all authenticate. (The registration route deliberately does
	// not — establishing identity is its purpose.)
	for _, e := range res.Surface.Entries {
		if !strings.HasPrefix(e.Path, "/api/orders") {
			continue
		}
		if len(e.Controls) == 0 {
			t.Fatalf("%s should carry requireAuth; the corpus premise is broken", e.Label())
		}
	}
	count := 0
	for _, f := range res.Taint.Findings {
		if f.Analysis == "unowned-record-access" {
			count++
		}
	}
	if count == 0 {
		t.Error("authenticated routes still need authorization; found none")
	}
}

// The check that separates enforcement from decoration.
//
// Both handlers compare the record's owner against the caller, in the same position,
// with the same operator. One returns 403 and stops; the other logs and continues.
// Position cannot tell them apart — only control flow can.
func TestIneffectiveCheckIsNotEnforcement(t *testing.T) {
	res := runScan(t, "express-idor")

	flagged := map[string]bool{}
	for _, f := range res.Taint.Findings {
		if f.Analysis == "unowned-record-access" {
			flagged[f.EntryPoint] = true
		}
	}

	if !flagged["GET /api/orders/:id/audited [express]"] {
		t.Error("a check whose branches reconverge decides nothing and must not count")
	}
	if flagged["GET /api/orders/:id/guarded [express]"] {
		t.Error("a check that returns early does gate the handler and must count")
	}
	if flagged["GET /api/orders/:id/detail [express]"] {
		t.Error("an early-returning check is enforcement regardless of statement order")
	}
}

// A judgement that cannot be evaluated is reported as unevaluated, never as satisfied
// (ADR-003). Stripping control flow must not silently turn ownership findings clean.
func TestOwnershipPolicyIsSkippedWithoutControlFlow(t *testing.T) {
	doc := loadCorpusIR(t, "express-idor")
	doc.Frontend.Capabilities.ControlFlow = false

	res := taint.Analyze(doc, model.Builtin())

	for _, f := range res.Findings {
		if f.Analysis == "unowned-record-access" {
			t.Errorf("ownership cannot be judged without control flow: %+v", f)
		}
	}
	var found bool
	for _, s := range res.Skipped {
		if s.PolicyID == "unowned-record-access" {
			found = true
			if len(s.Missing) != 1 || s.Missing[0] != "controlFlow" {
				t.Errorf("want missing=[controlFlow], got %v", s.Missing)
			}
		}
	}
	if !found {
		t.Error("an unevaluated policy must be reported, not silently dropped")
	}
}
