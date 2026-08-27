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
