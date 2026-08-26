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

	// doms and reachedFromEntry are built on first use; see computeDominators.
	doms             map[string]map[string]bool
	reachedFromEntry map[string]bool
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

// --- dominance and reachability -------------------------------------------
//
// Post-dominance answers "does this happen BECAUSE of that check". The opposite
// direction answers a different question that a redefinition needs: "has this
// definitely already happened by the time we get here". A variable assigned twice is
// lowered as one value with two edges into it, and telling a live definition from a
// dead one is exactly dominance plus reachability -- the later definition kills the
// earlier one for a use only if it is unavoidable on the way to that use and the
// earlier one cannot run again afterwards.
//
// Computed lazily: every caller of Build today asks only about post-dominance, and
// making them all pay for a second fixpoint would be a cost with no reader.

// Dominates reports whether every path from the function's entry to `b` passes through
// `a`. A block that is not reachable from the entry dominates nothing and is dominated
// by nothing: dead code makes no claim in either direction.
func (g *Graph) Dominates(a, b string) bool {
	g.computeDominators()
	set, ok := g.doms[b]
	if !ok {
		return false
	}
	return set[a]
}

// Reachable reports whether control can arrive at this block from the entry at all.
//
// Both frontends open a fresh block after a `return`, so straight-line code that ends
// in one leaves an orphan behind it, and that orphan is linked as a predecessor of
// whatever comes next. Ignoring it is what makes a `try` whose `catch` returns dominate
// the code after it -- which is the whole shape this analysis was built for.
func (g *Graph) Reachable(b string) bool {
	g.computeDominators()
	return g.reachedFromEntry[b]
}

// Reaches reports whether control can get from `from` to `to` along one or more edges.
// A block reaches ITSELF only through a cycle, which is the question a loop asks.
func (g *Graph) Reaches(from, to string) bool {
	seen := make(map[string]bool, len(g.order))
	queue := append([]string(nil), g.blocks[from].Successors...)
	if _, ok := g.blocks[from]; !ok {
		return false
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if id == to {
			return true
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if b, ok := g.blocks[id]; ok {
			queue = append(queue, b.Successors...)
		}
	}
	return false
}

// computeDominators runs the standard iterative dataflow forward from the entry, over
// the reachable subgraph only.
func (g *Graph) computeDominators() {
	if g.doms != nil {
		return
	}

	g.reachedFromEntry = make(map[string]bool, len(g.order))
	queue := []string{g.entry}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if g.reachedFromEntry[id] {
			continue
		}
		g.reachedFromEntry[id] = true
		if b, ok := g.blocks[id]; ok {
			queue = append(queue, b.Successors...)
		}
	}

	all := make(map[string]bool, len(g.order))
	for _, id := range g.order {
		if g.reachedFromEntry[id] {
			all[id] = true
		}
	}

	g.doms = make(map[string]map[string]bool, len(g.order))
	for _, id := range g.order {
		if !g.reachedFromEntry[id] {
			continue
		}
		if id == g.entry {
			g.doms[id] = map[string]bool{id: true}
			continue
		}
		g.doms[id] = copySet(all)
	}

	for changed := true; changed; {
		changed = false
		for _, id := range g.order {
			if !g.reachedFromEntry[id] || id == g.entry {
				continue
			}
			var next map[string]bool
			for _, p := range g.preds[id] {
				if !g.reachedFromEntry[p] {
					continue
				}
				set := g.doms[p]
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

			if !sameSet(next, g.doms[id]) {
				g.doms[id] = next
				changed = true
			}
		}
	}
}
