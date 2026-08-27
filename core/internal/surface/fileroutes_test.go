package surface

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

// A page module the framework serves and nothing enumerated, with the second fact that
// says the framework hands it the request.
func page(path, paramName string) (ir.Module, *ir.Function) {
	fn := &ir.Function{
		ID:     path + "#<anonymous>:1",
		Name:   "<anonymous>",
		Module: path,
		Loc:    ir.Loc{File: path, Line: 1},
	}
	if paramName != "" {
		fn.Values = []*ir.Value{{ID: path + "$v0", Kind: ir.ValueParam, Name: paramName, Path: paramName}}
	}
	return ir.Module{ID: path, Path: path}, fn
}

// The route family missed WHOLE, which the unreached-function ratio cannot see.
//
// umami enumerated 129 of 129 `route.ts` files and 0 of 59 `page.tsx`, 37 of which are
// server components the framework calls with the caller's own path parameters. Its
// completeness ratio read clean -- an unenumerated handler reads no input the model
// recognizes, so it moves neither side of the fraction -- and the run reported five ASVS
// requirements satisfied over an application a third of whose addresses were never looked
// at. linkwarden did the same with six `getServerSideProps` pages.
func TestARouteFamilyTheEnumerationDoesNotContainIsNoticed(t *testing.T) {
	appPage, appFn := page("src/app/(main)/websites/[websiteId]/page.tsx", "params")
	pagesPage, pagesFn := page("apps/web/pages/login.tsx", "")
	pagesFn.Name = "getServerSideProps"
	enumerated, enumeratedFn := page("src/app/api/websites/route.ts", "")

	d := &ir.IR{
		Modules:   []ir.Module{appPage, pagesPage, enumerated},
		Functions: []*ir.Function{appFn, pagesFn, enumeratedFn},
		EntryPoints: []ir.EntryPoint{{
			FunctionID: enumeratedFn.ID, Kind: "http-route",
			Detail: map[string]string{"method": "GET", "path": "/api/websites", "module": enumerated.Path},
			Loc:    ir.Loc{File: enumerated.Path, Line: 1},
		}},
	}

	got := unenumeratedRoutes(ir.NewIndex(d))
	if len(got) != 2 {
		t.Fatalf("found %d unenumerated route files, want the App Router page and the Pages Router page: %+v", len(got), got)
	}
	if got[0].Module != pagesPage.Path {
		t.Errorf("first is %q, want the Pages Router page", got[0].Module)
	}
	if got[1].Module != appPage.Path {
		t.Errorf("second is %q, want the App Router page", got[1].Module)
	}
	for _, r := range got {
		if r.Evidence == "" {
			t.Errorf("%s is accused with no evidence a reader can check", r.Module)
		}
	}

	c := Completeness{UnenumeratedRoutes: got}
	if !c.Suspect(1) {
		t.Error("a surface missing a whole route family is not one anything can be asserted over")
	}
	// And the ratio, which is a different question, must still answer it its own way.
	if c.UnreachedShareSuspect(1) {
		t.Error("no input-reading function is unreached here; the share must not say otherwise")
	}
}

// The negative that decides whether this is usable at all.
//
// `pages/dashboard.tsx` next door to `pages/api/` is a React component with a
// directory-derived path and a default export, shaped exactly like a route. The frontend
// declines to enumerate the 38 files like it in one real application because doing so
// would bury the 54 that are real, and this must not contradict it: a page the framework
// hands nothing from the request serves markup no caller can steer.
func TestAPageTheFrameworkHandsNothingIsNotAMissingRoute(t *testing.T) {
	component, componentFn := page("apps/web/pages/dashboard.tsx", "")
	componentFn.Name = "Dashboard"
	nested, nestedFn := page("apps/web/pages/settings/[team].tsx", "")
	nestedFn.Name = "TeamSettings"
	// A reserved file is not an address, and an API route below `pages/api` is the other
	// half of the convention and is enumerated by the frontend already.
	document, documentFn := page("apps/web/pages/_document.tsx", "params")
	apiRoute, apiFn := page("apps/web/pages/api/v1/links/index.ts", "params")

	d := &ir.IR{
		Modules:   []ir.Module{component, nested, document, apiRoute},
		Functions: []*ir.Function{componentFn, nestedFn, documentFn, apiFn},
	}
	if got := unenumeratedRoutes(ir.NewIndex(d)); len(got) != 0 {
		t.Errorf("accused %d files that serve nothing a caller controls: %+v", len(got), got)
	}
}
