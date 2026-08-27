package surface

import (
	"path"
	"sort"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

// Addresses a framework serves from a file's PATH, that the enumeration does not contain.
//
// The unreached-function ratio is an INDIRECT measure of completeness: it asks how much
// of the code that reads request data the surface can reach, and infers from a large
// answer that routes were missed. It cannot see a route family that was missed WHOLE,
// because a handler nothing enumerates is also a handler whose request parameter no rule
// recognizes -- so it reads no caller input, is not counted, and the ratio stays clean.
//
// That is the failure this exists for, and it is the one that matters most, because it is
// indistinguishable from success. Measured on two applications at one revision:
//
//	umami       170 entry points, 129 of 129 `route.ts` files enumerated, 0 of 59
//	            `page.tsx` -- 37 of which are server components the framework calls with
//	            the caller's own path parameters. Reported 1 violated, 5 satisfied.
//	linkwarden   75 entry points, 54 of 56 `pages/api` files enumerated, 0 of 6 pages
//	            that define `getServerSideProps` and run on the server per request.
//	            Reported 2 violated, 3 satisfied.
//
// Both reported no INCOMPLETE line at all. Neither was hiding: nothing in either run
// mentioned the missing family, and "3 satisfied" is a claim about an application a third
// of whose addresses were never looked at.
//
// A PATH is the whole registration for these frameworks, so the file's existence is the
// evidence -- but the file existing is not enough on its own. `pages/dashboard.tsx` next
// door to `pages/api/` is a React component, and enumerating the 38 files like it in one
// real application would have buried the 54 that are real routes; the frontend declines
// them for exactly that reason and it is right to. So each convention here carries a
// SECOND fact, read out of the module itself, that says the framework hands this file the
// request: a server component's `params`/`searchParams`, or a Pages Router
// `getServerSideProps`. A page with neither serves markup that no caller can steer, and it
// is not counted.
//
// This states an absence, and it goes away by itself the day the enumeration covers these
// files -- which is where the fix belongs. Until then the report says so rather than
// reporting six requirements satisfied over the part of the program it could see.
type UnenumeratedRoute struct {
	// Module is the file the framework serves at an address of its own.
	Module string
	// Convention names the rule that makes this file an address.
	Convention string
	// Evidence is what proves the framework hands this file the caller's request. Named
	// so the claim can be checked rather than believed, the same reason UnreachedGroup
	// carries a sample.
	Evidence string
}

// The two conventions with a measured counterexample behind them. Both are Next.js, which
// is what the corpus holds; the shape generalizes (Remix, Nuxt, SvelteKit and Astro all
// serve a file at a path derived from its directory) and each addition needs its own
// second fact, so they are added when there is a program to measure them against rather
// than from documentation.
const (
	ConventionAppRouterPage   = "a Next.js App Router page (app/**/page)"
	ConventionPagesRouterPage = "a Next.js Pages Router page (pages/**, outside pages/api)"
)

// routeFileSuffixes are the extensions these frameworks load. A `.d.ts` declares types
// and serves nothing.
func isRouteFileExt(name string) bool {
	if strings.HasSuffix(name, ".d.ts") {
		return false
	}
	switch path.Ext(name) {
	case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs":
		return true
	}
	return false
}

// appRouterPage reports whether this path is a page the App Router serves.
//
// `app` is matched as a DIRECTORY anywhere above the file rather than at the repository
// root, for the reason the frontend matches `pages/api` as a suffix: the router sits under
// `src/` in one application and under `apps/web/` in the next.
func appRouterPage(p string) bool {
	dir, base := path.Split(p)
	if !isRouteFileExt(base) {
		return false
	}
	if strings.TrimSuffix(base, path.Ext(base)) != "page" {
		return false
	}
	for _, seg := range strings.Split(strings.Trim(dir, "/"), "/") {
		if seg == "app" {
			return true
		}
	}
	return false
}

// pagesRouterPage reports whether this path is a page the Pages Router serves, excluding
// `pages/api` -- which the frontend already enumerates -- and the framework's own
// reserved files, which are not addresses.
func pagesRouterPage(p string) bool {
	dir, base := path.Split(p)
	if !isRouteFileExt(base) {
		return false
	}
	switch strings.TrimSuffix(base, path.Ext(base)) {
	case "_app", "_document", "_error", "_middleware", "middleware":
		return false
	}
	segs := strings.Split(strings.Trim(dir, "/"), "/")
	for i, seg := range segs {
		if seg != "pages" {
			continue
		}
		// `pages/api` is the other half of the same convention and is enumerated
		// already; a file below it is a route this does not need to claim.
		if i+1 < len(segs) && segs[i+1] == "api" {
			return false
		}
		return true
	}
	return false
}

// unenumeratedRoutes finds the files a file-routing framework serves that no enumerated
// entry point names.
//
// Coverage is asked of the whole IR's entry points rather than of the application ones,
// because an example page that WAS enumerated is not a page that was missed -- and the
// candidate side is filtered to the application surface for the same reason a vendored
// route is not counted as one of the program's own (ADR-009).
func unenumeratedRoutes(ix *ir.Index) []UnenumeratedRoute {
	enumerated := make(map[string]bool)
	for _, ep := range ix.IR.EntryPoints {
		if m := ep.Detail["module"]; m != "" {
			enumerated[m] = true
		}
		if fn := ix.FuncByID[ep.FunctionID]; fn != nil {
			enumerated[fn.Module] = true
		}
		if ep.Loc.File != "" {
			enumerated[ep.Loc.File] = true
		}
	}

	// What each module holds, for the second fact each convention needs.
	servesRequest := make(map[string]string)
	for _, fn := range ix.IR.Functions {
		if _, ok := servesRequest[fn.Module]; ok {
			continue
		}
		if fn.Name == "getServerSideProps" {
			servesRequest[fn.Module] = "defines getServerSideProps, which runs on the server per request"
			continue
		}
		for _, v := range fn.Values {
			if v.Kind != ir.ValueParam {
				continue
			}
			if v.Name == "params" || v.Name == "searchParams" {
				servesRequest[fn.Module] = "a server component parameter `" + v.Name + "`, which the framework fills from the request"
				break
			}
		}
	}

	var out []UnenumeratedRoute
	for _, m := range ix.IR.Modules {
		if m.IsTest || enumerated[m.Path] {
			continue
		}
		var convention string
		switch {
		case appRouterPage(m.Path):
			convention = ConventionAppRouterPage
		case pagesRouterPage(m.Path):
			convention = ConventionPagesRouterPage
		default:
			continue
		}
		// An example's page is not the application's surface, on the same terms as an
		// example's route.
		if !ix.InApplicationSurface(ir.Loc{File: m.Path}) {
			continue
		}
		evidence, ok := servesRequest[m.Path]
		if !ok {
			continue
		}
		out = append(out, UnenumeratedRoute{Module: m.Path, Convention: convention, Evidence: evidence})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out
}
