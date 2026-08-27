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

func TestRepetitionsCarryEveryHeaderAndItsBound(t *testing.T) {
	fn := &ir.Function{
		EntryBlock: "entry",
		Blocks: []ir.Block{
			{ID: "entry", Successors: []string{"outer"}},
			{ID: "outer", Successors: []string{"outer-body", "exit"}, LoopHeader: true, LoopBound: "items"},
			{ID: "outer-body", Successors: []string{"inner"}},
			{ID: "inner", Successors: []string{"inner-body", "tail"}, LoopHeader: true},
			{ID: "inner-body", Successors: []string{"inner"}},
			{ID: "tail", Successors: []string{"outer"}},
			{ID: "exit"},
		},
	}
	g := Build(fn)
	repetitions := g.Repetitions("inner-body")
	if len(repetitions) != 2 {
		t.Fatalf("inner body repetitions = %v, want outer and inner", repetitions)
	}
	if repetitions[0].Header != "outer" || repetitions[0].Bound != "items" {
		t.Errorf("outer repetition = %+v, want header outer bounded by items", repetitions[0])
	}
	if repetitions[1].Header != "inner" || repetitions[1].Bound != "" {
		t.Errorf("inner repetition = %+v, want header inner with no stated bound", repetitions[1])
	}
	tail := g.Repetitions("tail")
	if len(tail) != 1 || tail[0].Header != "outer" {
		t.Errorf("outer tail repetitions = %v, want only outer", tail)
	}
	if g.Repeats("exit") {
		t.Error("the block after the loop does not repeat")
	}
}

func TestLoopHeaderWithoutABackEdgeDoesNotRepeat(t *testing.T) {
	fn := &ir.Function{
		EntryBlock: "entry",
		Blocks: []ir.Block{
			{ID: "entry", Successors: []string{"header"}},
			{ID: "header", Successors: []string{"body"}, LoopHeader: true, LoopBound: "once"},
			{ID: "body"},
		},
	}
	if Build(fn).Repeats("header") {
		t.Error("a marker without a back edge is not a repetition")
	}
}
