package reachdef_test

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/reachdef"
)

// The shapes below are written as IR directly rather than lowered from source, because
// what this package reasons about IS the IR: which block an edge sits in, and what the
// block graph says about the order of two of them. A frontend that stops emitting a
// block is the case these tests care most about, and it cannot be expressed in source.

func loc(line int) ir.Loc { return ir.Loc{File: "a.ts", Line: line, Column: 1} }

// straightLine is `entry -> use`, one block, everything in source order.
func straightLine() *ir.Function {
	return &ir.Function{
		ID:         "f",
		Name:       "handler",
		Module:     "a.ts",
		EntryBlock: "b0",
		Blocks:     []ir.Block{{ID: "b0"}},
		Values: []*ir.Value{
			{ID: "tainted", Kind: ir.ValueCallResult, Loc: loc(1)},
			{ID: "clean", Kind: ir.ValueCallResult, Loc: loc(2)},
			{ID: "x", Kind: ir.ValueLocal, Name: "x", Loc: loc(1)},
			{ID: "sunk", Kind: ir.ValueLocal, Loc: loc(3)},
		},
		Flows: []ir.Flow{
			{From: "tainted", To: "x", Kind: "assign", Loc: loc(1), Block: "b0"},
			{From: "clean", To: "x", Kind: "assign", Loc: loc(2), Block: "b0"},
			{From: "x", To: "sunk", Kind: "binary", Loc: loc(3), Block: "b0"},
		},
	}
}

func program(fns ...*ir.Function) *ir.IR {
	return &ir.IR{IRVersion: "0.13.0", Frontend: ir.Frontend{Name: "test"}, Functions: fns}
}

// sourceOf returns what the single use of `x` reads after the split.
func sourceOf(t *testing.T, out *ir.IR, kind string) string {
	t.Helper()
	for _, fn := range out.Functions {
		for _, f := range fn.Flows {
			if f.Kind == kind {
				return f.From
			}
		}
	}
	t.Fatalf("no %q flow in the result", kind)
	return ""
}

func TestUnconditionalRedefinitionKillsTheEarlierOne(t *testing.T) {
	out, versions := reachdef.Split(program(straightLine()))

	from := sourceOf(t, out, "binary")
	if from == "x" {
		t.Fatal("the use still reads the merged value; the dead definition was not killed")
	}
	if versions[from] != "x" {
		t.Fatalf("the use reads %q, which is not a version of x (versions: %v)", from, versions)
	}

	// The version must be fed by the SECOND definition and by nothing else.
	var feeders []string
	for _, fn := range out.Functions {
		for _, f := range fn.Flows {
			if f.To == from {
				feeders = append(feeders, f.From)
			}
		}
	}
	if len(feeders) != 1 || feeders[0] != "clean" {
		t.Fatalf("version fed by %v, want [clean]", feeders)
	}
}

func TestNoBlockOnADefinitionKeepsEveryFlow(t *testing.T) {
	// Exactly the loop case: the frontend declined to place the second assignment, so
	// nothing here may reason about where it sits.
	fn := straightLine()
	fn.Flows[1].Block = ""

	out, versions := reachdef.Split(program(fn))
	if got := sourceOf(t, out, "binary"); got != "x" {
		t.Fatalf("the use reads %q; a flow with no block must never kill anything", got)
	}
	if len(versions) != 0 {
		t.Fatalf("versions created with an unplaced definition: %v", versions)
	}
}

func TestConditionalRedefinitionKillsNothing(t *testing.T) {
	// b0 branches to b1 (the `if` body, which redefines) and to b2 (the use). A path
	// from the first definition to the use avoids the second one entirely.
	fn := straightLine()
	fn.Blocks = []ir.Block{
		{ID: "b0", Successors: []string{"b1", "b2"}, Terminator: "branch"},
		{ID: "b1", Successors: []string{"b2"}},
		{ID: "b2"},
	}
	fn.Flows[1].Block = "b1"
	fn.Flows[2].Block = "b2"

	out, versions := reachdef.Split(program(fn))
	if got := sourceOf(t, out, "binary"); got != "x" {
		t.Fatalf("the use reads %q; a definition that only sometimes runs kills nothing", got)
	}
	if len(versions) != 0 {
		t.Fatalf("versions created for a conditional redefinition: %v", versions)
	}
}

func TestSameLineRedefinitionKeepsTheEarlierOne(t *testing.T) {
	// `x = f(x)`: the read of the old value and the assignment of the new one are the
	// same statement, and treating the read as coming afterwards would break the chain
	// through every transform written this way.
	fn := straightLine()
	fn.Flows[1].Loc = loc(1)

	out, versions := reachdef.Split(program(fn))
	if got := sourceOf(t, out, "binary"); got != "x" {
		t.Fatalf("the use reads %q; two definitions on one line establish no order", got)
	}
	if len(versions) != 0 {
		t.Fatalf("versions created from two definitions on the same line: %v", versions)
	}
}

func TestDefinitionInAnotherFunctionKeepsEveryFlow(t *testing.T) {
	// A closure assigning a captured name. Nothing here orders code across a function
	// boundary, and a callback runs an unknown number of times at an unknown point.
	fn := straightLine()
	captured := fn.Flows[1]
	fn.Flows = append(fn.Flows[:1], fn.Flows[2])

	other := &ir.Function{
		ID: "g", Name: "callback", Module: "a.ts",
		EntryBlock: "g0",
		Blocks:     []ir.Block{{ID: "g0"}},
		Values:     []*ir.Value{{ID: "clean", Kind: ir.ValueCallResult, Loc: loc(9)}},
		Flows:      []ir.Flow{{From: captured.From, To: "x", Kind: "assign", Loc: loc(9), Block: "g0"}},
	}

	out, versions := reachdef.Split(program(fn, other))
	if got := sourceOf(t, out, "binary"); got != "x" {
		t.Fatalf("the use reads %q; a definition in another function must not kill one here", got)
	}
	if len(versions) != 0 {
		t.Fatalf("versions created across a function boundary: %v", versions)
	}
}

func TestSingleDefinitionIsUntouched(t *testing.T) {
	fn := straightLine()
	fn.Flows = []ir.Flow{fn.Flows[0], fn.Flows[2]}

	out, versions := reachdef.Split(program(fn))
	if got := sourceOf(t, out, "binary"); got != "x" {
		t.Fatalf("the use reads %q; a value with one definition is not a merge", got)
	}
	if len(versions) != 0 {
		t.Fatalf("versions created for a single definition: %v", versions)
	}
	if out.Functions[0] != fn {
		t.Fatal("the function was copied even though nothing changed")
	}
}

func TestUseBeforeTheRedefinitionStillReadsTheOldValue(t *testing.T) {
	// Two uses: one on line 1 (before the replacement) and one on line 3 (after). Only
	// the second may be rewired -- this is what keeps `x = "prefix" + x` intact.
	fn := straightLine()
	fn.Values = append(fn.Values, &ir.Value{ID: "early", Kind: ir.ValueLocal, Loc: loc(1)})
	fn.Flows = append(fn.Flows, ir.Flow{From: "x", To: "early", Kind: "template", Loc: loc(1), Block: "b0"})

	out, _ := reachdef.Split(program(fn))
	if got := sourceOf(t, out, "template"); got != "x" {
		t.Fatalf("the earlier use reads %q, want the merged value", got)
	}
	if got := sourceOf(t, out, "binary"); got == "x" {
		t.Fatal("the later use still reads the merged value")
	}
}

func TestCallArgumentsAndReceiversAreRewired(t *testing.T) {
	fn := straightLine()
	fn.Flows = fn.Flows[:2]
	fn.Calls = []*ir.Call{{
		ID:         "c0",
		Loc:        loc(3),
		Block:      "b0",
		Callee:     ir.Callee{Kind: "external", Symbol: "console.log", Resolution: ir.Resolved},
		ReceiverID: "x",
		Args:       []ir.Arg{{Index: 0, ValueID: "x"}},
	}}

	out, versions := reachdef.Split(program(fn))
	c := out.Functions[0].Calls[0]
	if versions[c.ReceiverID] != "x" {
		t.Fatalf("receiver is %q, want a version of x", c.ReceiverID)
	}
	if versions[c.Args[0].ValueID] != "x" {
		t.Fatalf("argument 0 is %q, want a version of x", c.Args[0].ValueID)
	}
	// The input must not have been mutated: the pass copies what it changes.
	if fn.Calls[0].ReceiverID != "x" {
		t.Fatal("Split mutated the call it was given")
	}
}
