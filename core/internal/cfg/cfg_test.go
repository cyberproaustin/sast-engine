package cfg

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

func TestSelectedBySuccessorKeepsBranchPolarity(t *testing.T) {
	fn := &ir.Function{
		EntryBlock: "check",
		Blocks: []ir.Block{
			{ID: "check", Successors: []string{"reject", "accepted"}, Terminator: "branch"},
			{ID: "reject", Terminator: "return"},
			{ID: "accepted", Successors: []string{"other-check"}},
			{ID: "other-check", Successors: []string{"other-exit", "sink"}, Terminator: "branch"},
			{ID: "other-exit", Terminator: "return"},
			{ID: "sink", Terminator: "return"},
		},
	}
	g := Build(fn)
	if !g.SelectedBySuccessor("sink", "check", 1) {
		t.Error("the sink is reachable only through the accepted successor")
	}
	if g.SelectedBySuccessor("sink", "check", 0) {
		t.Error("the rejection successor does not reach the sink")
	}
}

func TestSelectedBySuccessorRefusesReconvergence(t *testing.T) {
	fn := &ir.Function{
		EntryBlock: "check",
		Blocks: []ir.Block{
			{ID: "check", Successors: []string{"warn", "accepted"}, Terminator: "branch"},
			{ID: "warn", Successors: []string{"sink"}},
			{ID: "accepted", Successors: []string{"sink"}},
			{ID: "sink", Terminator: "return"},
		},
	}
	if Build(fn).SelectedBySuccessor("sink", "check", 1) {
		t.Error("both outcomes reach the sink, so the condition constrains nothing")
	}
}
