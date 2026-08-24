// Package cfg answers control-flow questions about a lowered function.
//
// The question that matters for security is not "did a check appear before this?" but
// "does this operation happen BECAUSE of that check?" — control dependence, not
// dominance. A guard that returns 403 decides whether the response executes. A guard
// that only logs does not, and dominance cannot tell them apart: both come first.
package cfg

import "github.com/cyberproaustin/sast-engine/core/internal/ir"

// Graph is the control-flow graph of one function.
type Graph struct {
	entry    string
	blocks   map[string]*ir.Block
	order    []string
	preds    map[string][]string
	postDoms map[string]map[string]bool
}

// Build constructs the graph. Returns nil when the frontend supplied no blocks, so
// callers can distinguish "no control flow information" from "no control dependence"
// (ADR-003).
func Build(fn *ir.Function) *Graph {
	if len(fn.Blocks) == 0 || fn.EntryBlock == "" {
		return nil
	}

	g := &Graph{
		entry:  fn.EntryBlock,
		blocks: make(map[string]*ir.Block, len(fn.Blocks)),
		preds:  make(map[string][]string, len(fn.Blocks)),
	}
	for i := range fn.Blocks {
		b := fn.Blocks[i]
		g.blocks[b.ID] = &b
		g.order = append(g.order, b.ID)
	}
	for _, b := range g.blocks {
		for _, s := range b.Successors {
			if _, ok := g.blocks[s]; ok {
				g.preds[s] = append(g.preds[s], b.ID)
			}
		}
	}
	g.computePostDominators()
	return g
}

// exits are blocks control leaves the function from.
func (g *Graph) exits() []string {
	var out []string
	for _, id := range g.order {
		if len(g.blocks[id].Successors) == 0 {
			out = append(out, id)
		}
	}
	return out
}

// computePostDominators runs the standard iterative dataflow on the reversed graph.
// Post-dominance is what makes control dependence expressible: a block that is
// unavoidable on the way out cannot have been decided by a branch.
func (g *Graph) computePostDominators() {
	g.postDoms = make(map[string]map[string]bool, len(g.order))
	all := make(map[string]bool, len(g.order))
	for _, id := range g.order {
		all[id] = true
	}

	exits := g.exits()
	isExit := make(map[string]bool, len(exits))
	for _, e := range exits {
		isExit[e] = true
	}

	for _, id := range g.order {
		if isExit[id] {
			g.postDoms[id] = map[string]bool{id: true}
			continue
		}
		g.postDoms[id] = copySet(all)
	}

	for changed := true; changed; {
		changed = false
		for i := len(g.order) - 1; i >= 0; i-- {
			id := g.order[i]
			if isExit[id] {
				continue
			}
			succs := g.blocks[id].Successors
			if len(succs) == 0 {
				continue
			}

			var next map[string]bool
			for _, s := range succs {
				set, ok := g.postDoms[s]
				if !ok {
					continue
				}
				if next == nil {
					next = copySet(set)
					continue
				}
				for k := range next {
					if !set[k] {
						delete(next, k)
					}
				}
			}
			if next == nil {
				next = map[string]bool{}
			}
			next[id] = true

			if !sameSet(next, g.postDoms[id]) {
				g.postDoms[id] = next
				changed = true
			}
		}
	}
}

// PostDominates reports whether every path from `from` to an exit passes through `a`.
func (g *Graph) PostDominates(a, from string) bool {
	set, ok := g.postDoms[from]
	if !ok {
		return false
	}
	return set[a]
}

// ControlDependsOn reports whether `block` executes because of the branch at
// `branch` — that is, whether the branch has one successor that leads unavoidably to
// `block` and another that does not.
//
// This is the difference between a check that gates an operation and a check that
// merely precedes it.
func (g *Graph) ControlDependsOn(block, branch string) bool {
	b, ok := g.blocks[branch]
	if !ok || len(b.Successors) < 2 {
		return false
	}
	var reaches, avoids bool
	for _, s := range b.Successors {
		if g.PostDominates(block, s) {
			reaches = true
		} else {
			avoids = true
		}
	}
	return reaches && avoids
}

// IsGuard reports whether a branch decides that the handler may STOP: some path out
// of it leaves the function without rejoining the main line.
//
// This is the property that separates enforcement from decoration. A block whose
// branches all reconverge has a common post-dominator — whatever it tested, execution
// continues the same way. A guard has none: one side leaves.
//
//	if (owner !== caller) { res.status(403); return; }   // guard: one side exits
//	if (owner !== caller) { log("mismatch"); }           // not a guard: both continue
//
// Position cannot tell these apart. Both come before the operation.
func (g *Graph) IsGuard(block string) bool {
	b, ok := g.blocks[block]
	if !ok || len(b.Successors) < 2 {
		return false
	}
	// The block always post-dominates itself; anything more is a reconvergence point.
	return len(g.postDoms[block]) == 1
}

// AnyGuard reports whether any of the given blocks is a guard.
func (g *Graph) AnyGuard(blocks []string) bool {
	for _, b := range blocks {
		if g.IsGuard(b) {
			return true
		}
	}
	return false
}

func copySet(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
