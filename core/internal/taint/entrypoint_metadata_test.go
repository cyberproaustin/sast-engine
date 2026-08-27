package taint_test

// What a route SAYS about itself, as opposed to whether it was found at all.
//
// A route enumerated with the wrong verb, the wrong framework, the wrong path or the
// wrong function is not a smaller version of the truth: it is a false statement about the
// surface, and the surface is the primary output every other judgement rests on
// (ADR-009). None of these facts is expressible as a finding, so none of them is covered
// by the corpus scores — which is exactly how four of them were wrong at once.
//
// Regenerate the goldens these read with `make testdata`.

import (
	"sort"
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

// routeLabels renders one line per entry point: framework, verb, path.
func routeLabels(doc *ir.IR) []string {
	out := make([]string, 0, len(doc.EntryPoints))
	for _, ep := range doc.EntryPoints {
		out = append(out, strings.Join([]string{
			ep.Framework, ep.Detail["method"], ep.Detail["path"],
		}, " "))
	}
	sort.Strings(out)
	return out
}

func assertRoutes(t *testing.T, corpus string, want []string) {
	t.Helper()
	got := routeLabels(loadCorpusIR(t, corpus))
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("%s: want %d entry points, got %d:\n  %s", corpus, len(want), len(got),
			strings.Join(got, "\n  "))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s: entry point %d\n  want %q\n  got  %q", corpus, i, want[i], got[i])
		}
	}
}

// Flask defaults to GET when `methods=` is ABSENT. That default was being applied even
// where the argument was present, which recorded every POST-capable route of a search
// engine's web application as GET-only — and a GET-only label makes a whole class of
// body-based bypasses unaskable.
func TestFlaskDecoratorMetadata(t *testing.T) {
	assertRoutes(t, "flask-route-metadata", []string{
		// One decorator, two verbs.
		"flask GET /search",
		"flask POST /search",
		// `methods=` absent: Flask's GET default is right and stays right.
		"flask GET /health",
		// A blueprint's own url_prefix is the first half of the address, and a tuple
		// declares verbs exactly as a list does.
		"flask POST /admin/purge",
		// A path concatenated over an environment variable, which used to lower to `*`.
		"flask GET /hub/whoami",
		// A prefix that genuinely cannot be read, marked unresolved and NAMED rather
		// than printed as `*` — which would claim the route matches everything.
		"flask GET <unresolved:_runtime_prefix>/callback",
		// The framework belongs to the decorator's RECEIVER, not to whatever the file
		// imports: an APIRouter's routes are fastapi in a directory that is otherwise
		// entirely Flask, and the router's prefix composes into each path.
		"fastapi GET /api/v1/items",
		"fastapi POST /api/v1/items",
	})
}

// `@mock.patch("app.subprocess")` is spelled exactly like a verb decorator. A surface
// that invents entry points is worse than one that misses them, so a verb decorator on a
// receiver the file never watched being constructed is a route only when its first
// argument is a path.
func TestMockDecoratorIsNotARoute(t *testing.T) {
	for _, label := range routeLabels(loadCorpusIR(t, "flask-route-metadata")) {
		if strings.Contains(label, "app.subprocess") {
			t.Errorf("a unittest.mock decorator was enumerated as a route: %q", label)
		}
	}
}

// A configured base path and a router's mount prefix are both part of a route's address,
// and both were being printed as `*`.
func TestExpressPathsCarryTheirMountPrefix(t *testing.T) {
	assertRoutes(t, "express-route-metadata", []string{
		"express GET /api/v2/orders/:id",
		// `.route(path).get(h).post(h)` puts the path on a call of its own, so the verb
		// calls have none — and every route registered that way recorded `*`.
		"express GET /api/v2/things",
		"express POST /api/v2/things",
		"express GET /metrics",
		"express GET <unresolved:runtimePrefix>/callback",
	})
}

// The handler is the argument the framework calls LAST. Anchoring to the last argument
// the frontend could RESOLVE walked back past an unresolvable factory call and named the
// route's authentication middleware as its handler — a false statement about the one
// function every judgement about that route is made against.
func TestExpressAnchorsTheEntryToTheHandler(t *testing.T) {
	doc := loadCorpusIR(t, "express-route-metadata")

	var found bool
	for _, ep := range doc.EntryPoints {
		if ep.Detail["path"] != "/metrics" {
			continue
		}
		found = true
		if strings.Contains(ep.FunctionID, "auth.js") {
			t.Errorf("/metrics is anchored to its auth middleware (%s), not to its handler",
				ep.FunctionID)
		}
		// The handler is a factory call from a package outside the tree. The route still
		// exists, and what its handler was WRITTEN as is recorded, so an unresolved
		// handler is a named gap rather than a blank.
		if got := ep.Detail["handler"]; got != "prometheusMetrics()" {
			t.Errorf("want the unresolved handler named, got %q", got)
		}
		// And the middleware it displaced is where it belongs: on the route, as a control.
		var controls []string
		for _, m := range ep.Middleware {
			controls = append(controls, m.Name)
		}
		if !contains(controls, "apiAuth") {
			t.Errorf("apiAuth should be a control on /metrics, got %v", controls)
		}
	}
	if !found {
		t.Fatal("the /metrics route was not enumerated at all")
	}

	// The route whose handler DOES resolve is anchored to the handler and not to the
	// same middleware standing in front of it.
	for _, ep := range doc.EntryPoints {
		if ep.Detail["path"] == "/api/v2/orders/:id" && !strings.Contains(ep.FunctionID, "showOrder") {
			t.Errorf("want /api/v2/orders/:id anchored to showOrder, got %q", ep.FunctionID)
		}
	}
}

func contains(haystack []string, want string) bool {
	for _, s := range haystack {
		if s == want {
			return true
		}
	}
	return false
}

// A registration that is not a registration.
//
// `http.post("/api/drive/files", handler)` from Mock Service Worker is an identifier, a
// verb, a path literal and a function -- the same four tokens an Express route is
// written with -- and it answers a fetch the browser makes to itself inside a component
// story. 58 of one repository's 141 entry points were these, so 41% of the surface the
// engine claimed the application answered was a Storybook mock, and the receiver is
// called `http`: exactly the case where a resolved type was never going to arrive.
//
// The assertion is on the SURFACE because that is what was wrong. Over-reporting it is
// worse than under-reporting it (ADR-009), so the other half of this test matters just
// as much: three registrations survive, two of them on receivers nothing can type.
func TestMockHandlersAreNotRoutes(t *testing.T) {
	assertRoutes(t, "msw-not-express", []string{
		// The application, on a binding watched being created.
		"express POST /users",
		// One module that mocks one API and serves another: the exclusion is per
		// identifier, and `app` is not the identifier the mock library handed it.
		"express GET /health",
		// A router that arrives as a parameter. There is no binding to find and the
		// shape is the evidence -- still a route, and dropping it would trade one wrong
		// number for another.
		"express POST /things",
		// A Fastify registration on an untyped receiver. It answers requests, so it is
		// enumerated. That it is LABELLED express is a separate defect about metadata,
		// recorded here rather than quietly asserted as correct.
		"express GET /status",
	})

	// Named individually, because "four entry points" is a count and the thing that was
	// wrong was WHICH four.
	for _, ep := range loadCorpusIR(t, "msw-not-express").EntryPoints {
		if strings.Contains(ep.FunctionID, "mocks.ts") {
			t.Errorf("an msw handler is enumerated as a route: %s %s",
				ep.Detail["method"], ep.Detail["path"])
		}
		if strings.Contains(ep.FunctionID, ".stories.") {
			t.Errorf("a story's handler is enumerated as a route: %s %s",
				ep.Detail["method"], ep.Detail["path"])
		}
		if ep.Detail["path"] == "/api/meta" {
			t.Error("the msw handler in a module that also serves routes was admitted with them")
		}
		// The end-to-end runner's scaffolding, which is the same defect through a
		// different door: `cy.intercept("GET", "/api/admin/user", handler)` is a stub for
		// a request the test makes, and one application's surface carried it as a route.
		if strings.Contains(ep.FunctionID, "cypress/") {
			t.Errorf("a test runner's interceptor is enumerated as a route: %s %s",
				ep.Detail["method"], ep.Detail["path"])
		}
	}
}
