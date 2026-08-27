package taint_test

import (
	"os"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

// A statement that has already left the function reaches nothing.
//
// This is the invariant both frontends break in exactly one way, and it is the whole of
// the try/catch defect stated as a property. The exception edge belongs to the try
// REGION; hung on the first block of the BODY instead, it makes a handler the successor
// of whatever the body ended up doing -- and a body that ends in `return
// res.status(405).json(...)` terminates that very block, so the block is marked as
// leaving the function AND carries an edge to the handler. Two production handlers were
// reported at error level for that, and the Python frontend had no try/catch blocks at
// all until it could be built with the correction already in it.
//
// Asserted over every corpus rather than over the two that were written for it, because
// the shape appears wherever a frontend hangs an edge on a block after terminating it,
// and nothing about that failure is visible in a score: the graph merely says an
// operation is unavoidable when it is not, and the finding that results looks like any
// other finding.
func TestTerminatedBlocksHaveNoSuccessors(t *testing.T) {
	for _, name := range corpora {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open("testdata/" + name + ".ir.json")
			if err != nil {
				t.Fatalf("open corpus IR: %v", err)
			}
			defer f.Close()

			doc, err := ir.Load(f)
			if err != nil {
				t.Fatalf("load corpus IR: %v", err)
			}

			for _, fn := range doc.Functions {
				for _, b := range fn.Blocks {
					if b.Terminator != "return" && b.Terminator != "throw" {
						continue
					}
					if len(b.Successors) > 0 {
						t.Errorf("%s: block %s at %s ends in %q and still has %d successor(s): %v",
							fn.ID, b.ID, b.Loc, b.Terminator, len(b.Successors), b.Successors)
					}
				}
			}
		})
	}
}

// Repetition is a frontend fact, so this assertion reads golden output from both
// languages rather than constructing the desired graph by hand. The TypeScript corpus
// is the one kept beside the withdrawn CWE-834 shape; the Python corpus supplies the
// same language construct through the other frontend without adding a finding to either.
func TestBothFrontendsEmitLoopHeadersBoundsAndBackEdges(t *testing.T) {
	tests := []struct {
		corpus string
		loops  int
	}{
		{corpus: "unbounded-resource", loops: 4},
		{corpus: "flask-archive-extract", loops: 2},
	}
	for _, tt := range tests {
		t.Run(tt.corpus, func(t *testing.T) {
			f, err := os.Open("testdata/" + tt.corpus + ".ir.json")
			if err != nil {
				t.Fatalf("open corpus IR: %v", err)
			}
			defer f.Close()
			doc, err := ir.Load(f)
			if err != nil {
				t.Fatalf("load corpus IR: %v", err)
			}

			loops := 0
			for _, fn := range doc.Functions {
				graph := cfg.Build(fn)
				for _, block := range fn.Blocks {
					if !block.LoopHeader {
						continue
					}
					loops++
					if block.LoopBound == "" {
						t.Errorf("%s: loop header %s at %s has no extent value", fn.ID, block.ID, block.Loc)
					}
					if graph == nil || !graph.Repeats(block.ID) {
						t.Errorf("%s: loop header %s at %s has no reachable back edge", fn.ID, block.ID, block.Loc)
					}
				}
			}
			if loops != tt.loops {
				t.Errorf("loop headers = %d, want %d", loops, tt.loops)
			}
		})
	}
}

func TestComputedComparisonOperandSurvivesTypeScriptLowering(t *testing.T) {
	f, err := os.Open("testdata/unbounded-resource.ir.json")
	if err != nil {
		t.Fatalf("open corpus IR: %v", err)
	}
	defer f.Close()
	doc, err := ir.Load(f)
	if err != nil {
		t.Fatalf("load corpus IR: %v", err)
	}

	for _, fn := range doc.Functions {
		values := make(map[string]*ir.Value, len(fn.Values))
		for _, value := range fn.Values {
			values[value.ID] = value
		}
		for _, comparison := range fn.Comparisons {
			right := values[comparison.Right]
			if right == nil || right.Name != "arithmetic" {
				continue
			}
			operands := 0
			for _, flow := range fn.Flows {
				if flow.To == right.ID && flow.Kind == "arithmetic" {
					operands++
				}
			}
			if operands == 2 {
				return
			}
		}
	}
	t.Error("the `ids.length > 24 * 30` comparison has no computed right operand")
}

// A `try` states three things, and the corpus written for it is where each one is
// checked against a real lowering rather than a hand-built graph.
//
// The handler is reachable -- an edge MOVED to the region, not deleted, which is what
// keeps the two true findings that live inside catch blocks. It is not reached from a
// block that returns. And the line after a `try` whose every path returns is reached
// only from the handler, which is the shape that was mistaken for a fallthrough.
func TestPythonTryRegionCarriesTheExceptionEdge(t *testing.T) {
	f, err := os.Open("testdata/python-try-except.ir.json")
	if err != nil {
		t.Fatalf("open corpus IR: %v", err)
	}
	defer f.Close()

	doc, err := ir.Load(f)
	if err != nil {
		t.Fatalf("load corpus IR: %v", err)
	}

	// `archives` is the returning body: `if request.method == "POST": return ...` and
	// `return ...` beside it, with an `except` that falls through to a final response.
	var fn *ir.Function
	for _, f := range doc.Functions {
		if f.Name == "archives" {
			fn = f
		}
	}
	if fn == nil {
		t.Fatal("the corpus no longer contains the returning-body handler")
	}

	blocks := make(map[string]ir.Block, len(fn.Blocks))
	for _, b := range fn.Blocks {
		blocks[b.ID] = b
	}
	reached := map[string]bool{}
	queue := []string{fn.EntryBlock}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if reached[id] {
			continue
		}
		reached[id] = true
		queue = append(queue, blocks[id].Successors...)
	}

	// The handler holds the only call in this function that is not a response: the
	// warning it logs. Finding it by its call rather than by an index into the block
	// list keeps this test about the graph and not about how many blocks a lowering
	// happens to make.
	var handler string
	for _, c := range fn.Calls {
		if c.Method == "warning" {
			handler = c.Block
		}
	}
	if handler == "" {
		t.Fatal("the corpus no longer logs from the handler")
	}
	if !reached[handler] {
		t.Error("the handler is unreachable: the exception edge was deleted rather than moved")
	}
	for _, b := range fn.Blocks {
		for _, s := range b.Successors {
			if s == handler && (b.Terminator == "return" || b.Terminator == "throw") {
				t.Errorf("block %s leaves the function and still has an edge to the handler", b.ID)
			}
		}
	}
}
