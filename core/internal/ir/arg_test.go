package ir

import "testing"

func TestNamedArgumentBindsOnlyByName(t *testing.T) {
	fn := &Function{Params: []Param{
		{Index: 0, Name: "self", ValueID: "self"},
		{Index: 1, Name: "login_error", ValueID: "error"},
		{Index: 2, Name: "username", ValueID: "username"},
	}}
	arg := Arg{Name: "username", ValueID: "caller"}

	if arg.At(0) {
		t.Fatal("a keyword argument answered a positional index")
	}
	got, ok := arg.BoundParam(fn)
	if !ok || got.ValueID != "username" {
		t.Fatalf("username bound to %#v, %v; want the parameter named username", got, ok)
	}
}

func TestUnresolvedNamedArgumentHasNoPosition(t *testing.T) {
	arg := Arg{Name: "login_error", ValueID: "caller"}
	for index := 0; index < 3; index++ {
		if arg.At(index) {
			t.Fatalf("login_error claimed positional index %d without a callee", index)
		}
	}
}

// A destructuring pattern binds several parameters out of ONE argument, so an index is no
// longer a unique key and "which parameter does this argument become" has no answer.
func TestDestructuredParametersShareAnIndexAndAreNotWhatTheArgumentBecomes(t *testing.T) {
	fn := &Function{Params: []Param{
		{Index: 0, Name: "id", ValueID: "id", Destructured: true, Path: "id"},
		{Index: 0, Name: "teamId", ValueID: "team", Destructured: true, Path: "teamId"},
		{Index: 1, Name: "options", ValueID: "options"},
	}}
	arg := Arg{Index: 0, ValueID: "caller"}

	if p, ok := arg.BoundParam(fn); ok {
		t.Fatalf("a destructured parameter answered as what the argument becomes: %#v", p)
	}
	bound := arg.BoundParams(fn)
	if len(bound) != 2 || bound[0].ValueID != "id" || bound[1].ValueID != "team" {
		t.Fatalf("argument 0 bound %#v; want both destructured parameters", bound)
	}
	// The ordinary parameter beside them is unaffected in both directions.
	second := Arg{Index: 1, ValueID: "caller2"}
	if p, ok := second.BoundParam(fn); !ok || p.ValueID != "options" {
		t.Fatalf("argument 1 bound %#v, %v; want the options parameter", p, ok)
	}
	if got := second.BoundParams(fn); len(got) != 1 || got[0].ValueID != "options" {
		t.Fatalf("argument 1 bound %#v; want exactly the options parameter", got)
	}
}

// A NAMED argument addresses a parameter the callee declared. A destructured binding's
// name is a property of the argument, not a name a caller may pass -- and no language
// lowered here offers both forms, so matching them would invent a binding the callee
// cannot receive.
func TestANamedArgumentDoesNotBindADestructuredName(t *testing.T) {
	fn := &Function{Params: []Param{
		{Index: 0, Name: "id", ValueID: "binding", Destructured: true, Path: "id"},
	}}
	arg := Arg{Name: "id", ValueID: "caller"}

	if _, ok := arg.BoundParam(fn); ok {
		t.Fatal("a keyword argument bound a destructured binding by its property name")
	}
	if got := arg.BoundParams(fn); len(got) != 0 {
		t.Fatalf("a keyword argument bound %#v; want nothing", got)
	}
}
