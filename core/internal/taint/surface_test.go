package taint_test

// Surface and convention tests live beside the taint tests because they share the
// generated corpus goldens in testdata/. Regenerate with `make testdata`.

import (
	"os"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/expectation"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/policy"
	"github.com/cyberproaustin/sast-engine/core/internal/scan"
	"github.com/cyberproaustin/sast-engine/core/internal/surface"
)

func buildSurface(t *testing.T, doc *ir.IR, m model.Model) surface.Surface {
	t.Helper()
	return surface.Build(doc, m, nil)
}

// A corpus may declare a policy beside its sources; most do not, which is the normal
// state and must behave differently from an empty one.
func loadPolicy(t *testing.T, name string) *policy.Policy {
	t.Helper()
	p, err := policy.LoadFile("testdata/" + name + ".policy.json")
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	return p
}

func loadCorpusIR(t *testing.T, name string) *ir.IR {
	t.Helper()
	f, err := os.Open("testdata/" + name + ".ir.json")
	if err != nil {
		t.Fatalf("open corpus IR: %v", err)
	}
	defer f.Close()
	doc, err := ir.Load(f)
	if err != nil {
		t.Fatalf("load corpus IR: %v", err)
	}
	return doc
}

func runScan(t *testing.T, name string) scan.Result {
	t.Helper()
	return scan.Run(loadCorpusIR(t, name), model.Builtin(), loadPolicy(t, name))
}

// The surface is the primary output (ADR-009): a report is only as trustworthy as
// the enumeration it rests on.
func TestSurfaceEnumeratesEntryPointsAndControls(t *testing.T) {
	res := runScan(t, "express-authz")

	if len(res.Surface.Entries) != 7 {
		t.Fatalf("want 7 entry points, got %d", len(res.Surface.Entries))
	}

	byLabel := map[string]int{}
	for _, e := range res.Surface.Entries {
		byLabel[e.Label()] = len(e.Controls)
	}

	// Middleware is not a handler. Treating every function argument as an entry
	// point both invents routes and hides the controls guarding the real one.
	for _, notARoute := range []string{"requireAuth", "requireAdmin"} {
		if _, found := byLabel[notARoute]; found {
			t.Errorf("%s was enumerated as an entry point; it is middleware", notARoute)
		}
	}

	if got := byLabel["DELETE /api/orders/:id"]; got != 0 {
		t.Errorf("DELETE route should carry no controls, got %d", got)
	}
	if got := byLabel["GET /api/admin/stats"]; got != 2 {
		t.Errorf("admin route should carry 2 controls, got %d", got)
	}
}

// The flagship case: a defect that is an absence, with the peer population as its
// evidence (ADR-009, ADR-010).
func TestConventionFindsDeviationFromPeers(t *testing.T) {
	res := runScan(t, "express-authz")

	if !res.Expectation.Applicable {
		t.Fatalf("expectation analysis not applicable: %v", res.Expectation.MissingCapabilities)
	}

	inferred := inferredOnly(res.Expectation.Findings)
	if len(inferred) != 1 {
		t.Fatalf("want 1 inferred deviation, got %d: %+v", len(inferred), inferred)
	}

	f := inferred[0]
	if f.EntryPoint != "DELETE /api/orders/:id" {
		t.Errorf("wrong entry point flagged: %s", f.EntryPoint)
	}
	if f.MissingName != "requireAuth" {
		t.Errorf("want missing requireAuth, got %s", f.MissingName)
	}
	if f.Peers != 7 || f.Conforming != 5 {
		t.Errorf("want 5 of 7 conforming, got %d of %d", f.Conforming, f.Peers)
	}
	if len(f.ConformingList) != 5 {
		t.Errorf("the population is the evidence; want 5 peers listed, got %d", len(f.ConformingList))
	}
	if f.Origin != expectation.OriginInferred {
		t.Errorf("expectation origin must be stated, got %q", f.Origin)
	}
}

// Detection must not depend on recognizing the control by name (ADR-010). These are
// in-house middleware; the engine classifies them only as a convenience.
func TestConventionDoesNotDependOnNameRecognition(t *testing.T) {
	m := model.Builtin()
	m.Controls = nil // strip every known control name

	doc := loadCorpusIR(t, "express-authz")
	res := expectation.Analyze(doc, buildSurface(t, doc, m), m, nil, expectation.DefaultThresholds())

	// No policy is passed here, so the health route is not exempt and deviates too.
	inferred := inferredOnly(res.Findings)
	if len(inferred) != 2 {
		t.Fatalf("deviations must still be found with no control names known, got %d", len(inferred))
	}
	for _, f := range inferred {
		if f.ControlKind != "" {
			t.Errorf("kind should be unclassified with no rules, got %q", f.ControlKind)
		}
	}
}

// A control used by a minority is not the convention. requireAdmin appears on 1 of 5
// routes, and inferring a requirement from that would flag four correct routes.
func TestRareControlIsNotTreatedAsConvention(t *testing.T) {
	res := runScan(t, "express-authz")
	for _, f := range res.Expectation.Findings {
		if f.MissingName == "requireAdmin" {
			t.Errorf("requireAdmin (1 of 5) must not become an expectation: %+v", f)
		}
	}
}

// Inferred expectations inform; they never fail a build (ADR-005, ADR-010).
func TestConventionFindingsNeverGate(t *testing.T) {
	res := runScan(t, "express-authz")

	if len(res.Expectation.Findings) == 0 {
		t.Fatal("expected at least one deviation to test gating behavior")
	}
	for _, f := range res.Expectation.Findings {
		if f.Origin == expectation.OriginInferred && f.Gates {
			t.Errorf("an inferred expectation must not gate: %+v", f)
		}
	}
	// This corpus also carries a declared expectation, which does gate — so gating
	// must come from that and never from the inferred deviation.
	for _, f := range res.Expectation.Findings {
		if f.Gates && f.Origin != expectation.OriginDeclared {
			t.Errorf("only a declared expectation may gate, got %+v", f)
		}
	}
}

func inferredOnly(findings []expectation.Finding) []expectation.Finding {
	var out []expectation.Finding
	for _, f := range findings {
		if f.Origin == expectation.OriginInferred {
			out = append(out, f)
		}
	}
	return out
}

// Without a population there is no convention to deviate from. Silence here is the
// correct answer, not a missed detection.
func TestNoPopulationProducesNoDeviations(t *testing.T) {
	for _, name := range []string{"clean-express", "express-async", "express-command-injection"} {
		t.Run(name, func(t *testing.T) {
			res := runScan(t, name)
			if len(res.Expectation.Findings) != 0 {
				t.Errorf("want no deviations without a shared convention, got %d: %+v",
					len(res.Expectation.Findings), res.Expectation.Findings)
			}
		})
	}
}
