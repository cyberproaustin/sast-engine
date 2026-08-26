package taint_test

// Surface and convention tests live beside the taint tests because they share the
// generated corpus goldens in testdata/. Regenerate with `make testdata`.

import (
	"os"
	"strings"
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

// The other Next.js router, whose files name a path and no verb at all.
//
// Nothing here is registered and nothing names a method, so the whole surface is derived:
// the path from the directory below `pages/api`, and the verbs from the branches the
// handler takes on `req.method`. An application built this way enumerated ZERO entry
// points against 54 handlers before the convention was modelled.
//
// The set is asserted exactly, in both directions. `pages/` without `api/` is the other
// half of this same convention and holds React components with the identical shape --
// directory-derived path, default-exported function -- so a rule that is slightly too
// generous does not lose a route, it fills the surface with pages no caller can reach,
// and ADR-009 makes the enumeration the thing every finding rests on.
func TestPagesRouterSurfaceIsDerivedFromFilesAndBranches(t *testing.T) {
	res := runScan(t, "next-pages-router")

	want := map[string]bool{
		// No branch on the method: this handler really does answer all of them.
		"ANY /api/health": true,
		// `index` is the directory itself, and an if-chain is two reachable handlers.
		"GET /api/v1/links":  true,
		"POST /api/v1/links": true,
		// The parameter is in the FILE name, and a switch dispatches the same way.
		"GET /api/v1/links/:id":    true,
		"PUT /api/v1/links/:id":    true,
		"DELETE /api/v1/links/:id": true,
		// `req.method !== "POST"` is the 405 guard, and it names POST.
		"POST /api/webhooks/stripe": true,
		// Catch-all and optional catch-all.
		"ANY /api/proxy/*":  true,
		"ANY /api/legacy/*": true,
	}

	got := map[string]bool{}
	for _, e := range res.Surface.Entries {
		got[e.Label()] = true
	}
	for label := range want {
		if !got[label] {
			t.Errorf("missing entry point %s", label)
		}
	}
	for label := range got {
		if !want[label] {
			t.Errorf("%s was enumerated and is not a route", label)
		}
	}

	// Said again as a property rather than a list, because the list only holds while
	// this corpus does: what makes a file a route is the directory it is in.
	for _, e := range res.Surface.Entries {
		if module := e.EntryPoint.Detail["module"]; !strings.Contains(module, "pages/api/") {
			t.Errorf("%s was enumerated from %s, which is not an API route file", e.Label(), module)
		}
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

// Whether an anti-CSRF token is required at all is a fact about how a program
// authenticates, not about a line of code: on an API reached with a bearer header a token
// buys nothing. So this weakness is only ever decidable from the population -- the
// program declares that its routes are reached with a cookie by carrying the check on its
// other routes, and the one that does not carry it is the deviation.
//
// It is the clearest case for ADR-010 in the whole model, which is why it is the one that
// gets a test of its own rather than a line in a table.
func TestConventionNamesMissingCsrfAsCsrf(t *testing.T) {
	res := runScan(t, "express-csrf")

	if !res.Expectation.Applicable {
		t.Fatalf("expectation analysis not applicable: %v", res.Expectation.MissingCapabilities)
	}
	inferred := inferredOnly(res.Expectation.Findings)
	if len(inferred) != 1 {
		t.Fatalf("want 1 inferred deviation, got %d: %+v", len(inferred), inferred)
	}
	f := inferred[0]
	if f.EntryPoint != "POST /profile/password" {
		t.Errorf("wrong entry point flagged: %s", f.EntryPoint)
	}
	// The deviation is one judgement -- this route lacks what its peers have -- and what
	// makes it a particular weakness is WHAT was lacking (ADR-012).
	if f.CWE != "CWE-352" {
		t.Errorf("a missing anti-CSRF control is CWE-352, got %s", f.CWE)
	}
}

// A module specifier that only a `tsconfig.json` can explain.
//
// `@/lib/controllers/deleteLinks` is neither a package nor a relative path: it is the
// project's own alias, and `@/` is what a Next.js application is scaffolded with. A
// specifier that resolves to nothing lowers the call as EXTERNAL, so the caller's data
// taints the call's result instead of entering the callee's parameter and the whole
// controller layer reads as unreachable -- which is what hid linkwarden's bulk endpoints
// and what put umami's DOMAIN_REGEX out of reach through `@/lib/constants`.
//
// Asserted on the callee rather than only on the findings, because a resolution that
// happens to reach a sink and a resolution that is CORRECT are different claims, and the
// negatives can only be stated here: nothing is reported for a call that stays external,
// and "no finding" is what a resolver inventing callees would also produce.
func TestPathAliasesResolveWithinTheDeclaringProject(t *testing.T) {
	doc := loadCorpusIR(t, "tsconfig-path-alias")

	type site struct{ module, written string }
	calls := map[site]ir.Callee{}
	for _, fn := range doc.Functions {
		for _, c := range fn.Calls {
			if c.Callee.Name != "" {
				calls[site{fn.Module, c.Callee.Name}] = c.Callee
			}
		}
	}

	// Each of these crosses a boundary only the alias table spans, and each by a
	// different mechanism the compiler's own resolver already implements.
	resolved := map[site]string{
		// `"@/*": ["./generated/*", "./*"]` -- the first target has nothing under it,
		// so the second answers. A multi-target array is tried in order.
		{"apps/web/pages/api/links.ts", "deleteLinks"}: "apps/web/lib/controllers/deleteLinks.ts#deleteLinks:9:1",
		// The first target, when it does answer.
		{"apps/web/pages/api/links.ts", "describeModel"}: "apps/web/generated/models.ts#describeModel:5:1",
		// `@/lib/db` names a DIRECTORY; `index.ts` is the file.
		{"apps/web/pages/api/links.ts", "runQuery"}: "apps/web/lib/db/index.ts#runQuery:5:1",
		// `@shared/*` is declared two directories up and reached by following
		// `apps/api/tsconfig.json`'s `extends`.
		{"apps/api/routes.ts", "auditLog"}: "packages/shared/src/audit.ts#auditLog:6:1",
		// A workspace package NAME, mapped without a wildcard at all.
		{"apps/api/routes.ts", "runReport"}: "packages/shared/src/index.ts#runReport:6:1",
	}
	for where, want := range resolved {
		got, found := calls[where]
		if !found {
			t.Errorf("%s in %s: no call site lowered at all", where.written, where.module)
			continue
		}
		if got.Kind != "local" || got.FunctionID != want {
			t.Errorf("%s in %s: want local %s, got %s %s",
				where.written, where.module, want, got.Kind, got.FunctionID)
		}
	}

	// An alias table states what a project's OWN names mean. `@ui/widgets` matches no
	// mapping and nothing on disk answers it, and `@/lib/db` is `apps/web`'s alias --
	// the identical specifier written in `apps/api`, whose config never declared it.
	// A mapping is per-directory or it is a resolver answering for a project that made
	// no such claim.
	for _, where := range []site{
		{"apps/web/pages/api/links.ts", "renderWidget"},
		{"apps/api/routes.ts", "runQuery"},
	} {
		got, found := calls[where]
		if !found {
			t.Errorf("%s in %s: no call site lowered at all", where.written, where.module)
			continue
		}
		if got.Kind != "external" {
			t.Errorf("%s in %s: no mapping reaches it, want external, got %s %s",
				where.written, where.module, got.Kind, got.FunctionID)
		}
	}
}
