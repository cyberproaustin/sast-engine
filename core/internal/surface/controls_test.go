package surface

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
)

// route builds an entry point whose handler is fn.
func route(d *ir.IR, method, path string, fn *ir.Function) {
	d.EntryPoints = append(d.EntryPoints, ir.EntryPoint{
		FunctionID: fn.ID, Kind: "http-route", Framework: "express",
		Detail: map[string]string{"method": method, "path": path},
		Loc:    fn.Loc,
	})
}

// localCall is how an application calls a control it wrote itself: resolved to a function
// in the tree, no external symbol, and the written name is the only name there is.
func localCall(id, name, target string, line int) *ir.Call {
	return &ir.Call{
		ID:  id,
		Loc: ir.Loc{File: "app.ts", Line: line},
		Callee: ir.Callee{
			Kind: "local", Name: name, FunctionID: target, Resolution: ir.Resolved,
		},
	}
}

// A control an application DEFINES ITSELF was invisible to control detection, because the
// lookup read the method name and the external symbol and a local call has neither.
//
// Measured across ten unmodified repositories: 32 of 1613 entry points carried any
// control at all, and linkwarden -- which calls `verifyUser` or `verifyToken` on the first
// line of every API route it serves -- carried none on any of its 75. `verifyToken` was
// already in the model. Nothing was ever compared against it.
func TestAControlTheApplicationDefinesItselfIsSeen(t *testing.T) {
	guard := &ir.Function{ID: "auth#verifyToken", Name: "verifyToken", Module: "auth.ts",
		Loc: ir.Loc{File: "auth.ts", Line: 1}}
	handler := &ir.Function{ID: "app#handler", Name: "handler", Module: "app.ts",
		Loc:   ir.Loc{File: "app.ts", Line: 10},
		Calls: []*ir.Call{localCall("c1", "verifyToken", guard.ID, 11)}}

	d := doc(handler, guard)
	route(d, "GET", "/reports", handler)

	s := Build(d, model.Builtin(), nil)
	if len(s.Entries) != 1 {
		t.Fatalf("want one entry point, got %d", len(s.Entries))
	}
	e := s.Entries[0]
	if len(e.Controls) != 1 || e.Controls[0].Kind != "authentication" {
		t.Fatalf("want one authentication control on the handler, got %+v", e.Controls)
	}
	if !e.Authenticates {
		t.Error("a route whose handler verifies a token authenticates its caller")
	}
}

// A route that dispatches before it does anything is the shape a Next.js page route has,
// and it is where linkwarden's eight adjudicated disclosures sit: `Index` -> `handlePost`
// -> `verifyUser({req, res})`. The control is not attached to the entry point and the
// caller was still asked who they are, so the two facts are reported apart.
func TestAControlOneHopBelowTheHandlerStillAuthenticates(t *testing.T) {
	guard := &ir.Function{ID: "auth#verifyUser", Name: "verifyUser", Module: "auth.ts",
		Loc: ir.Loc{File: "auth.ts", Line: 1}}
	post := &ir.Function{ID: "app#handlePost", Name: "handlePost", Module: "app.ts",
		Loc:   ir.Loc{File: "app.ts", Line: 20},
		Calls: []*ir.Call{localCall("c2", "verifyUser", guard.ID, 21)}}
	index := &ir.Function{ID: "app#Index", Name: "Index", Module: "app.ts",
		Loc:   ir.Loc{File: "app.ts", Line: 40},
		Calls: []*ir.Call{localCall("c3", "handlePost", post.ID, 41)}}

	d := doc(index, post, guard)
	route(d, "POST", "/reports", index)

	e := Build(d, model.Builtin(), nil).Entries[0]
	if len(e.Controls) != 0 {
		t.Errorf("nothing is ATTACHED to this entry point; Controls is what peers are compared on (ADR-010), got %+v", e.Controls)
	}
	if !e.Authenticates {
		t.Error("the handler's first act is to call something that asks who the caller is")
	}
}

// And no further. Two hops below a handler reaches every helper an application owns, at
// which point a static file mount comes out authenticated because something deep beneath
// it eventually asks who you are -- and a fact that is true of everything ranks nothing.
func TestAuthenticationTwoHopsBelowIsNotThisEntryPointsControl(t *testing.T) {
	guard := &ir.Function{ID: "auth#requireLogin", Name: "requireLogin", Module: "auth.ts",
		Loc: ir.Loc{File: "auth.ts", Line: 1}}
	deep := &ir.Function{ID: "lib#load", Name: "load", Module: "lib.ts",
		Loc:   ir.Loc{File: "lib.ts", Line: 5},
		Calls: []*ir.Call{localCall("c4", "requireLogin", guard.ID, 6)}}
	mid := &ir.Function{ID: "app#render", Name: "render", Module: "app.ts",
		Loc:   ir.Loc{File: "app.ts", Line: 20},
		Calls: []*ir.Call{localCall("c5", "load", deep.ID, 21)}}
	handler := &ir.Function{ID: "app#serve", Name: "serve", Module: "app.ts",
		Loc:   ir.Loc{File: "app.ts", Line: 40},
		Calls: []*ir.Call{localCall("c6", "render", mid.ID, 41)}}

	d := doc(handler, mid, deep, guard)
	route(d, "GET", "/static/*", handler)

	if Build(d, model.Builtin(), nil).Entries[0].Authenticates {
		t.Error("an authentication call three functions away is not this route asking who the caller is")
	}
}

// A route with nothing on it is the case the rank is FOR, so it has to come out false
// rather than merely unknown.
func TestARouteWithNoControlDoesNotAuthenticate(t *testing.T) {
	handler := &ir.Function{ID: "app#status", Name: "status", Module: "app.ts",
		Loc: ir.Loc{File: "app.ts", Line: 10}}
	d := doc(handler)
	route(d, "GET", "/status", handler)

	if Build(d, model.Builtin(), nil).Entries[0].Authenticates {
		t.Error("nothing on this route asks who the caller is")
	}
}
