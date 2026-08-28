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

// Provenance changes the population and rank, never whether source was analyzed.
// jupyterhub's nine example routes made a zero-coverage run read partly successful;
// uptime-kuma's checked-in protocol package put upstream crypto beside application
// findings. The fixture holds both sides so removing either is a regression.
func TestNonFirstPartyCodeIsReportedOutsideTheApplicationSurface(t *testing.T) {
	res := runScan(t, "non-first-party-code")

	if got := len(res.Surface.Entries); got != 3 {
		t.Fatalf("application surface has %d entries, want 3", got)
	}
	if got := len(res.Surface.NonApplicationEntries); got != 5 {
		t.Fatalf("non-application surface has %d entries, want 5", got)
	}

	wantOrigin := map[string]ir.Provenance{
		"examples/demo.ts":                 ir.Example,
		"generated/table.ts":               ir.Generated,
		"nested-package/index.ts":          ir.Vendored,
		"server/modules/licensed/index.ts": ir.Vendored,
		"server/modules/modified/index.ts": ir.Vendored,
		"vendor/library.ts":                ir.Vendored,
	}
	gating := 0
	seen := map[string]bool{}
	for _, finding := range res.Taint.Findings {
		seen[finding.SinkLoc.File] = true
		if got, want := finding.Provenance, wantOrigin[finding.SinkLoc.File]; got != want {
			t.Errorf("%s provenance = %q, want %q", finding.SinkLoc.File, got, want)
		}
		if res.Gates(finding) {
			gating++
		}
	}
	if len(seen) != 8 {
		t.Errorf("reported findings from %d modules, want all 8", len(seen))
	}
	if gating != 2 {
		t.Errorf("%d findings gate, want only the two hand-written application findings", gating)
	}
	if got := res.Surface.Completeness.InputFunctions; got != 1 {
		t.Errorf("completeness counted %d input-reading functions, want only the application function", got)
	}

	// Recreate the failure mode: the frontend saw an example registration and none of
	// the application's. Its presence must not turn zero application routes into one.
	doc := loadCorpusIR(t, "non-first-party-code")
	var examples []ir.EntryPoint
	for _, entry := range doc.EntryPoints {
		if strings.HasPrefix(entry.Loc.File, "examples/") {
			examples = append(examples, entry)
		}
	}
	doc.EntryPoints = examples
	exampleOnly := buildSurface(t, doc, model.Builtin())
	if len(exampleOnly.Entries) != 0 {
		t.Errorf("example-only program claims %d application entry points", len(exampleOnly.Entries))
	}
	if !exampleOnly.Completeness.Suspect(len(exampleOnly.Entries)) {
		t.Errorf("example-only surface is not suspect: %+v", exampleOnly.Completeness)
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

// A rendered page is a real remote entry and still not an API handler.
//
// umami has 59 of these beside 168 exported API methods. Folding the two populations
// would make a correct API count wrong in order to acknowledge code a caller can reach;
// dropping the pages makes their server-side searchParams flows unreachable. The kind is
// therefore part of the assertion, not presentation detail.
func TestAppRouterPagesAreCountedApartFromAPIRoutes(t *testing.T) {
	res := runScan(t, "app-router-pages")

	wantPages := map[string]string{
		"src/app/page.tsx": "GET /",
		"src/app/(main)/accounts/[accountId]/page.tsx":            "GET /accounts/:accountId",
		"src/app/(main)/search/page.tsx":                          "GET /search",
		"src/app/@modal/(.)accounts/[accountId]/details/page.tsx": "GET /accounts/:accountId/details",
	}
	gotPages := map[string]string{}
	httpRoutes := 0
	for _, entry := range res.Surface.Entries {
		switch entry.EntryPoint.Kind {
		case "rendered-page":
			gotPages[entry.EntryPoint.Detail["module"]] = entry.Label()
			if entry.EntryPoint.Framework != "next-app-page" {
				t.Errorf("%s framework = %q, want next-app-page", entry.Label(), entry.EntryPoint.Framework)
			}
		case "http-route":
			httpRoutes++
		default:
			t.Errorf("unexpected surface kind %q at %s", entry.EntryPoint.Kind, entry.Label())
		}
	}
	if httpRoutes != 1 {
		t.Errorf("API surface has %d routes, want only route.ts", httpRoutes)
	}
	for module, label := range wantPages {
		if gotPages[module] != label {
			t.Errorf("rendered page %s = %q, want %q", module, gotPages[module], label)
		}
	}
	for module, label := range gotPages {
		if _, ok := wantPages[module]; !ok {
			t.Errorf("%s from %s was enumerated but is not a real default-exported page component", label, module)
		}
	}

	classes := map[string]int{}
	for _, class := range res.Surface.Classes() {
		classes[class.Kind] = class.Count
	}
	if classes["rendered-page"] != 4 || classes["http-route"] != 1 {
		t.Errorf("surface classes = %#v, want rendered-page=4 and http-route=1", classes)
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

// A mount is an author-written comparison boundary. medplum declares publicRoutes and
// protectedRoutes in one file; comparing across those bindings produced CWE-306's only
// two findings in twenty repositories, both on deliberately public metadata handlers.
func TestConventionComparesOnlyWithinMount(t *testing.T) {
	res := runScan(t, "mounted-auth-comparison")
	inferred := inferredOnly(res.Expectation.Findings)
	if len(inferred) != 1 {
		t.Fatalf("want only the protected-mount deviation, got %d: %+v", len(inferred), inferred)
	}
	f := inferred[0]
	if f.EntryPoint != "GET /Medication" || f.CWE != "CWE-306" {
		t.Errorf("want CWE-306 on GET /Medication, got %+v", f)
	}
	if f.Peers != 4 || f.Conforming != 3 {
		t.Errorf("want 3 of 4 protected-mount peers conforming, got %d of %d", f.Conforming, f.Peers)
	}
}

// A caller who presents a secret has authenticated, whatever the population mounts.
//
// The population can only compare an entry point against what its peers MOUNT, and a
// signing link mounts nothing -- that is what makes it a link rather than a session.
// documenso measured the cost of reading the two as one question: enumerating its tRPC
// surface produced five CWE-306 findings and an independent reader judged all five false,
// every one a procedure that resolves a recipient from the token the caller sent.
//
// The four that survive are the reason the rule is narrow. One route has no control and
// no secret. One selects a record by `documentId` -- a value the caller sent and an
// identifier the caller can count through, which is the same shape as the token routes
// minus the only thing that makes them authentication. One hands `tokenId` to a helper
// that looks a row up by it, which is a primary key wearing a credential word. The fourth
// is a stated miss rather than a defect in the fixture, and it is asserted so that
// widening the binding rule cannot pass unnoticed.
func TestCallerPresentedCredentialIsNotAMissingControl(t *testing.T) {
	res := runScan(t, "credential-instead-of-session")

	silent := map[string]bool{"POST /sign/status": true, "POST /sign/field": true}
	mustFire := map[string]bool{
		"POST /documents/archive":       true,
		"DELETE /documents/:documentId": true,
		"POST /tokens/revoke":           true,
		// A STATED MISS, asserted so that widening the binding rule cannot pass
		// unnoticed. This route authenticates by token exactly as the two silent ones
		// do, and the token reaches the lookup as a bare positional argument -- which
		// the rule does not follow, because a position does not survive a receiver.
		// Binding by position is what made saleor's setPassword cite a lookup keyed by
		// the caller's password when the row is selected by the email.
		"POST /sign/complete": true,
	}

	got := map[string]bool{}
	for _, f := range inferredOnly(res.Expectation.Findings) {
		if silent[f.EntryPoint] {
			t.Errorf("%s authenticates by a credential the caller presented: %+v", f.EntryPoint, f)
		}
		if f.CWE != "CWE-306" {
			t.Errorf("want CWE-306 on %s, got %s", f.EntryPoint, f.CWE)
		}
		got[f.EntryPoint] = true
	}
	for label := range mustFire {
		if !got[label] {
			t.Errorf("%s has no authentication of any kind and must still report", label)
		}
	}
	if len(got) != len(mustFire) {
		t.Errorf("want exactly %d deviations, got %v", len(mustFire), got)
	}

	// Withdrawing an inference silently would be the same defect as suppressing a
	// finding silently: the reader cannot check what they cannot see.
	if len(res.Expectation.Withheld) != len(silent) {
		t.Fatalf("want %d withheld inferences, got %+v", len(silent), res.Expectation.Withheld)
	}
	for _, w := range res.Expectation.Withheld {
		if !silent[w.EntryPoint] {
			t.Errorf("withheld on an entry point that has no credential: %+v", w)
		}
		if w.Field != "token" || w.Selection == "" || w.Loc.File == "" {
			t.Errorf("a withheld inference must cite the field and the lookup: %+v", w)
		}
	}
}

// The fact itself, on the surface, because it is the one control this engine recognises
// that is not in the Controls list: nothing is mounted and the evidence is a lookup.
func TestSurfaceRecordsTheCredentialTheCallerPresented(t *testing.T) {
	res := runScan(t, "credential-instead-of-session")
	want := map[string]string{
		"POST /sign/status": "prisma.recipient.findFirst",
		"POST /sign/field":  "prisma.recipient.findFirstOrThrow",
	}
	for _, e := range res.Surface.Entries {
		selection, expected := want[e.Label()]
		switch {
		case expected && e.Credential == nil:
			t.Errorf("%s resolves a recipient from the caller's token and records no credential", e.Label())
		case expected && e.Credential.Selection != selection:
			t.Errorf("%s cites %q, want %q", e.Label(), e.Credential.Selection, selection)
		case !expected && e.Credential != nil:
			t.Errorf("%s records a credential it does not have: %+v", e.Label(), e.Credential)
		}
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

// The label is not decoration: it selects the source rules that seed a handler's
// parameters, and one application's 83 routes were recorded as express over a Fastify
// server. Every registration in this frontend is spelled `x.get(path, handler)`, so the
// shape cannot tell the two apart and the receiver has to.
func TestFrameworkComesFromTheReceiverNotTheShape(t *testing.T) {
	res := runScan(t, "fastify-routes")

	want := map[string]string{
		// `const fastify = Fastify()` -- the factory came from the framework's module.
		"GET /diag/ping":   "fastify",
		"POST /diag/trace": "fastify",
		// A parameter declared `FastifyInstance`, registering at a path held in a local
		// constant. Nothing else in that file looks like a route at all.
		"GET /admin/purge": "fastify",
		// Two frameworks in one tree is the ordinary case.
		"GET /legacy/health": "express",
	}

	got := map[string]string{}
	for _, e := range res.Surface.Entries {
		got[e.Label()] = e.EntryPoint.Framework
	}
	for label, framework := range want {
		if got[label] != framework {
			t.Errorf("%s: want framework %s, got %q", label, framework, got[label])
		}
	}
	for label := range got {
		if _, ok := want[label]; !ok {
			t.Errorf("%s was enumerated and is not a route", label)
		}
	}
}

// A described route's path is read the way every other registrar's is. Requiring a
// string literal matched 109 of one application's 208 descriptions, and the 99 misses
// were three spellings of the same thing rather than a different shape.
func TestDescribedRoutePathsResolveLikeEveryOtherRegistrar(t *testing.T) {
	res := runScan(t, "described-route-paths")

	want := map[string]bool{
		// `path: ''` is the router's own mount point, rejected by a truthiness test.
		"GET /": true,
		// The literal, which is the case that always worked.
		"GET /health": true,
		// A constant, and a constant built from constants.
		"GET /:projectId/features/:featureName/environments/:environment":      true,
		"POST /:projectId/features/:featureName/environments/:environment/off": true,
		// Genuinely unreadable, and it names the expression that stood in the way
		// rather than claiming `*`.
		"DELETE <unresolved:prefix>/:contextField": true,
	}

	assertSurface(t, res.Surface.Entries, want)
}

// A registration one hop from a registration. The wrapper proves itself -- one route
// description built out of its own parameters -- rather than being trusted for its name.
func TestForwardedRegistrarIsARegistration(t *testing.T) {
	res := runScan(t, "forwarded-registrar")

	want := map[string]bool{
		"GET /prometheus":     true,
		"GET /impact/metrics": true,
		"POST /heap-snapshot": true,
	}

	assertSurface(t, res.Surface.Entries, want)
}

// One call site, many addresses. A loop over a statically enumerable registry is folded
// once per element; a loop over a collection assembled at runtime is not folded at all.
func TestRegistryLoopExpandsOnlyWhatItCanEnumerate(t *testing.T) {
	res := runScan(t, "route-registry-loop")

	want := map[string]bool{
		// One row per endpoint and not two, though the loop registers in both branches
		// of a condition: an address exists once however many implementations sit
		// behind it. The prefix comes from `register(plugin, { prefix })`, which the
		// plugin's own file never states.
		"ALL /api/notesCreate": true,
		"ALL /api/notesDelete": true,
		"ALL /api/usersShow":   true,
		// The negative: nothing here knows what the environment holds.
		"GET /api/x/<unresolved:name>": true,
		"GET /api/healthz":             true,
		"GET /diag/ping":               true,
	}

	assertSurface(t, res.Surface.Entries, want)
}

// `add_url_rule`'s view_func is an EXPRESSION. The registration shape was modelled and
// the argument test was not, so a handler named through its module was refused -- and a
// route whose handler cannot be resolved still exists at its address.
func TestUrlRuleRegistersWhateverItsViewFuncIs(t *testing.T) {
	res := runScan(t, "flask-url-rule-alias")

	want := map[string]bool{
		// A bare name, and a module attribute resolved across a file boundary.
		"GET /local-search": true,
		"GET /report":       true,
		"POST /report":      true,
		// Re-exported through a package `__init__`, which the definition table does not
		// follow: the row carries no function and the address is still enumerated.
		"GET /favicon_proxy": true,
		// The class-based view, counted ONCE -- by its verb methods, not a second time
		// through the `as_view` registration that has no function behind it.
		"GET /preferences": true,
	}

	assertSurface(t, res.Surface.Entries, want)
}

// The set is asserted in BOTH directions wherever the surface is the expectation: a rule
// that is slightly too generous does not lose a route, it fills the enumeration with
// addresses nothing answers at, and ADR-009 makes the enumeration the thing every
// finding rests on.
func assertSurface(t *testing.T, entries []surface.EntryFacts, want map[string]bool) {
	t.Helper()

	got := map[string]bool{}
	for _, e := range entries {
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
}

// A directory served by a PLUGIN. The mount detector read `use` and nothing else, so a
// framework that mounts its file server with `register` put six directories on the
// network and none on the surface. The negatives are the whole of the rule's honesty:
// the same plugin registered with `serve: false` serves nothing.
func TestStaticPluginMountIsAnAddress(t *testing.T) {
	res := runScan(t, "static-plugin-mount")

	want := map[string]bool{
		// Root and prefix, which is what a file server is.
		"/assets/": true,
		// No prefix at all: the plugin's default is `/`, and an address stated by a
		// default is still the address the application answers at.
		"/": true,
		// Inside a plugin registered at `/files`, which the mount's own file never
		// states -- the same prefix that already travels to the routes.
		"/files/thumbs/": true,
	}

	got := map[string]bool{}
	for _, e := range res.Surface.Entries {
		if e.EntryPoint.Kind != "static-mount" {
			continue
		}
		got[e.Path] = true
	}
	for path := range want {
		if !got[path] {
			t.Errorf("missing static mount %s", path)
		}
	}
	for path := range got {
		if !want[path] {
			t.Errorf("%s was enumerated and is not a directory this application serves", path)
		}
	}

	// The route in the same file is untouched by any of it.
	routes := 0
	for _, e := range res.Surface.Entries {
		if e.EntryPoint.Kind == "http-route" {
			routes++
			if e.Label() != "GET /healthz" {
				t.Errorf("want GET /healthz, got %s", e.Label())
			}
		}
	}
	if routes != 1 {
		t.Errorf("want 1 route, got %d", routes)
	}
}
