package surface

import (
	"os"
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
)

// prop builds a function that reads `<param>.<path>` off the parameter at index i.
func prop(id, name, file string, params []string, base int, path string) *ir.Function {
	fn := &ir.Function{ID: id, Name: name, Module: file, Loc: ir.Loc{File: file, Line: 1, Column: 1}}
	for i, p := range params {
		vid := id + "$p" + string(rune('0'+i))
		fn.Params = append(fn.Params, ir.Param{Name: p, ValueID: vid})
		fn.Values = append(fn.Values, &ir.Value{ID: vid, Kind: "param", Name: p})
	}
	fn.Values = append(fn.Values, &ir.Value{
		ID:   id + "$v",
		Kind: ir.ValueProperty,
		Base: fn.Params[base].ValueID,
		Path: path,
	})
	return fn
}

func doc(fns ...*ir.Function) *ir.IR {
	d := &ir.IR{IRVersion: "0.1.0", Frontend: ir.Frontend{Name: "test"}, Functions: fns}
	seen := map[string]bool{}
	for _, fn := range fns {
		if !seen[fn.Loc.File] {
			seen[fn.Loc.File] = true
			d.Modules = append(d.Modules, ir.Module{ID: fn.Loc.File, Path: fn.Loc.File})
		}
	}
	return d
}

// The union of every framework's request shape, matched against ANY parameter, is not a
// claim about handler shape -- it is a claim about field names. searxng's engine plugins
// take an outbound request dict as their SECOND argument and set `params["url"]` on it,
// and they were counted as unreached request handlers because Express calls something
// else `req.url`. The position is part of the rule and it was being thrown away.
//
// It does not separate everything: Django's rule reaches parameter one, for methods
// written `def get(self, request)`, and its path list holds names as ordinary as
// `headers`. What survives that overlap is answered by the report rather than by the
// count -- see the by-cause listing, which says "67 in searx/engines" and lets a reader
// see what the number is made of.
func TestPositionSeparatesARequestFromADomainObject(t *testing.T) {
	handler := prop("h", "handler", "app/routes.py", []string{"req"}, 0, "body.name")
	plugin := prop("p", "request", "app/engines/duck.py", []string{"query", "params"}, 1, "url")

	c := Build(doc(handler, plugin), model.Builtin(), nil).Completeness
	if c.InputFunctions != 1 {
		t.Fatalf("InputFunctions = %d, want 1 (the handler only)", c.InputFunctions)
	}
	if c.UnreachedInputFunctions != 1 {
		t.Fatalf("UnreachedInputFunctions = %d, want 1", c.UnreachedInputFunctions)
	}
	for _, g := range c.Unreached {
		for _, s := range g.Sample {
			if s.Name == "request" {
				t.Fatalf("an engine plugin's outbound params dict counted as a request handler: %+v", s)
			}
		}
	}
}

// A function that cannot serve a request cannot be evidence that a route serving one was
// missed. 733 of healthchecks' 824 input-reading functions are in its test suite, and
// counting them said 745 of 824 unreached about a surface an adjudicator had just
// verified was complete.
func TestTestModulesAreCountedApartRatherThanAgainstTheSurface(t *testing.T) {
	live := prop("h", "view", "hc/front/views.py", []string{"request"}, 0, "POST")
	fixture := prop("t", "test_view", "hc/front/tests/test_views.py", []string{"request"}, 0, "POST")
	d := doc(live, fixture)
	for i := range d.Modules {
		if strings.Contains(d.Modules[i].Path, "/tests/") {
			d.Modules[i].IsTest = true
		}
	}

	c := Build(d, model.Builtin(), nil).Completeness
	if c.InputFunctions != 1 {
		t.Errorf("InputFunctions = %d, want 1", c.InputFunctions)
	}
	if c.NonProductionInputFunctions != 1 {
		t.Errorf("NonProductionInputFunctions = %d, want 1", c.NonProductionInputFunctions)
	}
}

// A count of unreachable code nobody can check is a count a reader learns to skip. Each
// unreached function must arrive with the reason the call graph gives for it.
func TestUnreachedFunctionsArriveWithACause(t *testing.T) {
	// Called by name from somewhere, through an edge that did not resolve.
	helper := prop("helper", "parse_body", "app/helpers.py", []string{"request"}, 0, "body")
	caller := &ir.Function{
		ID: "caller", Name: "dispatch", Module: "app/dispatch.py",
		Loc:   ir.Loc{File: "app/dispatch.py", Line: 1, Column: 1},
		Calls: []*ir.Call{{ID: "c0", Method: "parse_body", Callee: ir.Callee{Kind: "unresolved"}}},
	}
	// Called by a function that is itself unreached.
	below := prop("below", "read_headers", "app/helpers.py", []string{"request"}, 0, "headers")
	above := prop("above", "middle", "app/helpers.py", []string{"request"}, 0, "META")
	above.Calls = []*ir.Call{{ID: "c1", Callee: ir.Callee{Kind: "local", FunctionID: "below"}}}
	// Nothing anywhere writes this name: a framework invokes it, or it is dead.
	hook := prop("hook", "clean_identity", "app/forms.py", []string{"self"}, 0, "request")

	c := Build(doc(helper, caller, below, above, hook), model.Builtin(), nil).Completeness
	got := map[string]int{}
	for _, g := range c.Unreached {
		got[g.Cause] = g.Count
		if len(g.Sample) == 0 {
			t.Errorf("cause %q named no example", g.Cause)
		}
		if len(g.Modules) == 0 {
			t.Errorf("cause %q named no module", g.Cause)
		}
	}
	for cause, want := range map[string]int{
		CauseMissingCallEdge: 1,
		CauseBelowUnreached:  1,
		CauseNeverCalled:     2, // `middle` and the form hook
	} {
		if got[cause] != want {
			t.Errorf("cause %q counted %d, want %d (all: %v)", cause, got[cause], want, got)
		}
	}
}

// A registration names the subclass; the code that runs is on the base.
//
// The lowered corpus is read rather than hand-built, because what is being asserted is a
// property of the FRONTEND: that `self.parse_body()` written in a subclass resolves to
// the method its base class defines in another module. Measured on jupyterhub, 32 of the
// 55 functions that read request data and that no enumerated route could reach were
// inherited handler methods, and the surface reported INCOMPLETE over a route table an
// adjudicator had verified was complete.
//
// The golden lives with the taint corpora because it is generated by `make testdata` with
// every other corpus, and there is one copy of it on purpose.
func TestAnInheritedHandlerMethodIsPartOfTheSurface(t *testing.T) {
	f, err := os.Open("../taint/testdata/python-inherited-method.ir.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := ir.Load(f)
	if err != nil {
		t.Fatal(err)
	}

	s := Build(d, model.Builtin(), nil)
	if len(s.Entries) != 2 {
		t.Fatalf("entry points = %d, want 2", len(s.Entries))
	}
	c := s.Completeness
	if c.InputFunctions != 1 {
		t.Fatalf("InputFunctions = %d, want 1 (the inherited parse_body)", c.InputFunctions)
	}
	if c.UnreachedInputFunctions != 0 {
		t.Errorf("the base class's parse_body is unreached: %+v", c.Unreached)
	}
}
