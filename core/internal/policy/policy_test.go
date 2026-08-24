package policy_test

import (
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/policy"
)

// ADR-013 enforced by the loader, not merely documented. A suppression list must not
// be expressible, and must not be silently ignored either.
func TestSuppressionIsNotExpressible(t *testing.T) {
	doc := `{"version":1,"ignore":[{"rule":"CWE-639","file":"app.ts","line":41}]}`

	_, err := policy.Load(strings.NewReader(doc), "test")
	if err == nil {
		t.Fatal("a policy containing a suppression list must be rejected")
	}
	if !strings.Contains(err.Error(), "ADR-013") {
		t.Errorf("the error should say why, got: %v", err)
	}
}

// A declaration changes what the tool enforces. Requiring a stated rationale is what
// keeps it a fact about the application rather than a waiver.
func TestDeclarationRequiresAReason(t *testing.T) {
	doc := `{"version":1,"entryPoints":[{"match":{"pathPrefix":"/api"},"publicByDesign":true}]}`

	_, err := policy.Load(strings.NewReader(doc), "test")
	if err == nil {
		t.Fatal("a declaration without a reason must be rejected")
	}
	if !strings.Contains(err.Error(), "waiver") {
		t.Errorf("the error should explain the distinction, got: %v", err)
	}
}

// A match that selects nothing is a declaration that can never be evaluated.
func TestEmptyMatchIsRejected(t *testing.T) {
	doc := `{"version":1,"entryPoints":[{"match":{},"reason":"x"}]}`
	if _, err := policy.Load(strings.NewReader(doc), "test"); err == nil {
		t.Fatal("a rule matching nothing must be rejected")
	}
}

// No policy supplied is a different state from an empty one: the first means nothing
// has been stated, the second means someone stated nothing (ADR-011).
func TestAbsentPolicyIsDistinctFromEmpty(t *testing.T) {
	absent, err := policy.LoadFile("")
	if err != nil {
		t.Fatalf("absent policy should not error: %v", err)
	}
	if absent.Present {
		t.Error("no policy supplied must not report as present")
	}

	empty, err := policy.Load(strings.NewReader(`{"version":1}`), "test")
	if err != nil {
		t.Fatalf("empty policy should load: %v", err)
	}
	if !empty.Present {
		t.Error("an explicitly empty policy is present")
	}
}

// Declarations select by property, so they cover routes that do not exist yet.
func TestMatchingIsByProperty(t *testing.T) {
	p, err := policy.Load(strings.NewReader(
		`{"version":1,"entryPoints":[{"match":{"pathPrefix":"/api/admin"},
		  "requiresControls":["authorization"],"reason":"admin surface"}]}`), "test")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if got := p.RulesFor("GET", "/api/admin/anything-added-later", "g"); len(got) != 1 {
		t.Errorf("a prefix declaration should cover future routes, got %d rules", len(got))
	}
	if got := p.RulesFor("GET", "/api/orders", "g"); len(got) != 0 {
		t.Errorf("unrelated routes must not match, got %d rules", len(got))
	}
}

// Whether `auth.required` performs authentication is not derivable from its name.
// The team declares it; the engine never guesses from spelling (ADR-011).
func TestControlKindCanBeDeclared(t *testing.T) {
	p, err := policy.Load(strings.NewReader(`{"version":1,"controls":[
	  {"name":"auth.required","kind":"authentication","reason":"express-jwt guard"}]}`), "test")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := p.ClassifyControl("auth.required"); got != "authentication" {
		t.Errorf("want authentication, got %q", got)
	}
	if got := p.ClassifyControl("somethingElse"); got != "" {
		t.Errorf("undeclared names stay unclassified, got %q", got)
	}
}

// A control declaration changes what the tool enforces, so it needs a rationale too.
func TestControlDeclarationRequiresAReason(t *testing.T) {
	doc := `{"version":1,"controls":[{"name":"auth.required","kind":"authentication"}]}`
	if _, err := policy.Load(strings.NewReader(doc), "test"); err == nil {
		t.Fatal("a control declaration without a reason must be rejected")
	}
}
