package taint_test

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/expectation"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/scan"
)

// The asymmetry ADR-011 exists for: a team that wrote down what it expects gets it
// enforced; an inference about what it probably meant does not stop a build.
func TestDeclaredExpectationsGateAndInferredDoNot(t *testing.T) {
	res := runScan(t, "express-authz")

	var declared, inferred int
	for _, f := range res.Expectation.Findings {
		switch f.Origin {
		case expectation.OriginDeclared:
			declared++
			if !f.Gates {
				t.Errorf("a declared expectation must gate: %+v", f)
			}
			if f.DeclaredReason == "" {
				t.Errorf("a declared finding must carry the stated rationale: %+v", f)
			}
		case expectation.OriginInferred:
			inferred++
			if f.Gates {
				t.Errorf("an inferred expectation must not gate: %+v", f)
			}
		default:
			t.Errorf("every expectation states its origin, got %q", f.Origin)
		}
	}

	if declared == 0 || inferred == 0 {
		t.Fatalf("corpus should exercise both origins, got declared=%d inferred=%d", declared, inferred)
	}
	if !res.Gating() {
		t.Error("a violated declared expectation must fail the run")
	}
}

// Authentication is not authorization, and a declaration is how a team says so for its
// own surface. The admin route has requireAuth and still violates the declaration.
func TestDeclaredRequirementIsNotSatisfiedByADifferentControlKind(t *testing.T) {
	res := runScan(t, "express-authz")

	var found bool
	for _, f := range res.Expectation.Findings {
		if f.Origin == expectation.OriginDeclared && f.EntryPoint == "GET /api/admin/audit" {
			found = true
			if f.ControlKind != "authorization" {
				t.Errorf("want the authorization requirement, got %q", f.ControlKind)
			}
		}
	}
	if !found {
		t.Error("an authenticated route missing the declared authorization control must be reported")
	}
}

// A declaration silences an inference, but never silently: the effect is reported with
// the declaration and its stated reason (ADR-013).
func TestSuppressionIsRecordedNotSilent(t *testing.T) {
	res := runScan(t, "express-authz")

	if len(res.Expectation.Suppressed) == 0 {
		t.Fatal("the public-by-design declaration should have suppressed an inference")
	}
	s := res.Expectation.Suppressed[0]
	if s.EntryPoint != "GET /api/health" {
		t.Errorf("wrong entry point suppressed: %s", s.EntryPoint)
	}
	if s.Reason == "" || s.DeclaredBy == "" {
		t.Errorf("a suppression must name the declaration and its reason: %+v", s)
	}

	for _, f := range res.Expectation.Findings {
		if f.EntryPoint == "GET /api/health" && f.Origin == expectation.OriginInferred {
			t.Errorf("a suppressed inference must not also be reported: %+v", f)
		}
	}
}

// A declaration matching nothing is a stated expectation that was never checked.
// Reporting it as satisfied would be the same failure as a clean scan that never ran.
func TestDeclarationMatchingNothingIsReportedUnchecked(t *testing.T) {
	res := runScan(t, "express-authz")

	var found bool
	for _, u := range res.Expectation.UnmatchedRules {
		if u.Match == "/api/billing*" {
			found = true
			if u.Reason == "" {
				t.Error("an unchecked declaration should carry its reason")
			}
		}
	}
	if !found {
		t.Error("a declaration selecting no entry point must be reported as unchecked")
	}
}

// No policy supplied is not the same as a policy that permits everything.
func TestAbsentPolicyIsReportedAsAbsent(t *testing.T) {
	withPolicy := runScan(t, "express-authz")
	if !withPolicy.Expectation.PolicyPresent {
		t.Error("a supplied policy should report as present")
	}

	without := scan.Run(loadCorpusIR(t, "express-authz"), model.Builtin(), nil)
	if without.Expectation.PolicyPresent {
		t.Error("no policy must report as absent, not as an empty one")
	}
	if without.Expectation.Gating() {
		t.Error("with nothing declared, nothing can gate")
	}
	for _, f := range without.Expectation.Findings {
		if f.Origin == expectation.OriginDeclared {
			t.Errorf("no declarations exist, so none can be violated: %+v", f)
		}
	}
}
