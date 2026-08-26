// Package reachdef tells definitions of the same variable apart.
//
// A variable that is assigned twice reaches the core as ONE value with two edges into
// it. That is a merge, and a merge says "either of these could be what is here" -- which
// is true at a use that both definitions reach, and false at a use where the second
// assignment has already replaced the first. The frontend threw the difference away
// before the core ever saw it, and the core then reported the dead value.
//
// linkwarden's Stripe webhook is the measured case:
//
//	let event = req.body;                                       // line 46
//	event = stripe.webhooks.constructEvent(body, sig, secret);   // line 56, unconditional
//	const eventType = event.type;                                // line 62
//	console.log(`... ${eventType}`);                             // line 106 -- reported
//
// The line-56 assignment is unavoidable on the way to line 62 and the line-46 value is
// gone, and the engine reported the log as caller-controlled with a path back to line 46.
// The same shape is most of defensive code: `let x = req.query.x; x = sanitize(x);`.
//
// # What this does
//
// It is SSA renaming, done narrowly and only where it is certain. A use whose reaching
// definitions are a strict subset of a value's definitions is rewired to reference a
// fresh version of that value, fed by exactly those definitions. The original value
// keeps every definition it had and every use this pass could not position, so anything
// not understood here behaves exactly as it did before. No phi node is ever needed,
// because a use reached by more than one definition simply keeps reading the merge.
//
// # The bias
//
// A false negative costs more than a false positive, so every uncertainty resolves
// towards keeping the flow (ADR-003). A definition is killed for a use ONLY when the
// killing definition provably dominates that use and provably cannot be followed by the
// killed one. Everything else is left alone, including:
//
//   - a flow with no block, which is how both frontends decline to place an edge they
//     cannot vouch for -- inside a loop body, whose back edge is not emitted, and inside
//     a `switch`, whose arms are lowered straight-line;
//   - a value whose definitions do not all sit in one function, which is what a closure
//     capturing a variable looks like and which no ordering here would be sound over;
//   - a definition or a use in a block that is not reachable from the function's entry;
//   - a value that is anything but a plain local -- a parameter, a property, a global;
//   - two definitions on the SAME source line, where nothing establishes which ran
//     first. This is what keeps `x = "prefix" + x` intact: the read of `x` on that line
//     is not after the assignment on that line, so the earlier definition still reaches
//     it and the composition survives;
//   - a use the pass cannot position at all -- a return, a write into an object, a
//     comparison. Those keep reading the merged value.
package reachdef

import (
	"fmt"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

// Split returns a program in which uses with a single reaching definition read a
// version of the value rather than the merge, together with a map from each version
// back to the value it came from.
//
// The input is not mutated: functions that change are copied. The returned map is what
// lets a consumer of the analysis ask about the ORIGINAL value again, which is what
// every analysis outside this one still speaks in terms of.
func Split(d *ir.IR) (*ir.IR, map[string]string) {
	if d == nil {
		return d, nil
	}

	// Definitions of a value can be written in a function that does not own it: a
	// closure assigning a captured name, an implicit global. Collected across the whole
	// program so that case is VISIBLE here and can be declined, rather than looking like
	// a single-function value that happens to have one definition.
	defsOf := make(map[string][]defSite)
	for _, fn := range d.Functions {
		for i := range fn.Flows {
			f := fn.Flows[i]
			if f.From == "" || f.To == "" {
				continue
			}
			defsOf[f.To] = append(defsOf[f.To], defSite{fn: fn, index: i})
		}
	}

	versionOf := make(map[string]string)
	changed := make(map[string]*ir.Function)
	graphs := make(map[string]*cfg.Graph)

	for _, fn := range d.Functions {
		s := &splitter{fn: fn, defsOf: defsOf, versionOf: versionOf, graphs: graphs}
		if out := s.run(); out != nil {
			changed[fn.ID] = out
		}
	}
	if len(changed) == 0 {
		return d, versionOf
	}

	out := *d
	out.Functions = make([]*ir.Function, len(d.Functions))
	for i, fn := range d.Functions {
		if replacement, ok := changed[fn.ID]; ok {
			out.Functions[i] = replacement
			continue
		}
		out.Functions[i] = fn
	}
	return &out, versionOf
}

// defSite is one edge INTO a value: a definition of it.
type defSite struct {
	fn    *ir.Function
	index int
}

// use is one place a value is read, at a point the block graph can position.
type use struct {
	block string
	loc   ir.Loc
	// Exactly one of these identifies what to rewire.
	flow     int // index into the function's flows
	call     int // index into the function's calls
	arg      int // index into that call's args, or -1 for its receiver
	isCall   bool
	original string
}

type splitter struct {
	fn        *ir.Function
	defsOf    map[string][]defSite
	versionOf map[string]string
	graphs    map[string]*cfg.Graph

	// Rewrites accumulated for this function, applied to a copy at the end.
	flowFrom map[int]string
	callArg  map[[2]int]string
	receiver map[int]string
	added    []ir.Flow
	newVals  []*ir.Value
}

// run computes every rewrite for one function and returns a rewritten copy of it, or
// nil when nothing about this function changed.
func (s *splitter) run() *ir.Function {
	graph := s.graph(s.fn)
	if graph == nil {
		return nil
	}

	owned := make(map[string]*ir.Value, len(s.fn.Values))
	for _, v := range s.fn.Values {
		owned[v.ID] = v
	}

	for _, v := range s.fn.Values {
		defs, ok := s.definitionsOf(v, owned, graph)
		if !ok {
			continue
		}
		s.splitValue(v, defs, graph)
	}
	return s.rewritten()
}

// definitionsOf returns the definitions of a value when every precondition for
// reasoning about them holds, and reports false the moment one does not.
func (s *splitter) definitionsOf(v *ir.Value, owned map[string]*ir.Value, graph *cfg.Graph) ([]ir.Flow, bool) {
	// Only a plain local. A parameter has a definition at the function's entry that is
	// not an edge at all, a property is a read out of something else rather than a name
	// that gets reassigned, and a global can be written by code this pass never sees.
	if v.Kind != ir.ValueLocal || v.Base != "" || v.Path != "" {
		return nil, false
	}
	for _, p := range s.fn.Params {
		if p.ValueID == v.ID {
			return nil, false
		}
	}

	sites := s.defsOf[v.ID]
	if len(sites) < 2 {
		return nil, false
	}
	defs := make([]ir.Flow, 0, len(sites))
	for _, site := range sites {
		// A definition written in another function is a closure assigning a captured
		// name. Nothing here orders code across a function boundary, and a callback runs
		// an unknown number of times at an unknown point.
		if site.fn.ID != s.fn.ID {
			return nil, false
		}
		f := site.fn.Flows[site.index]
		// No block: the frontend declined to place this edge. Keeping every flow is the
		// only safe reading of that (ADR-003).
		if f.Block == "" || !graph.Reachable(f.Block) {
			return nil, false
		}
		defs = append(defs, f)
	}
	return defs, true
}

// splitValue rewires every use of v whose reaching definitions are a strict, non-empty
// subset of v's definitions.
func (s *splitter) splitValue(v *ir.Value, defs []ir.Flow, graph *cfg.Graph) {
	uses := s.usesOf(v.ID)
	if len(uses) == 0 {
		return
	}

	versions := make(map[string]string)
	for _, u := range uses {
		if !graph.Reachable(u.block) {
			continue
		}
		var reaching []int
		for i := range defs {
			if s.reaches(defs, i, u, graph) {
				reaching = append(reaching, i)
			}
		}
		// Every definition reaches: this use IS the merge, and reading the merged value
		// is exactly right. None reaches: the analysis has lost the thread, so leave it.
		if len(reaching) == 0 || len(reaching) == len(defs) {
			continue
		}

		key := fmt.Sprint(reaching)
		id, ok := versions[key]
		if !ok {
			id = fmt.Sprintf("%s#rd%d", v.ID, len(s.newVals))
			versions[key] = id
			clone := *v
			clone.ID = id
			s.newVals = append(s.newVals, &clone)
			s.versionOf[id] = v.ID
			for _, i := range reaching {
				edge := defs[i]
				edge.To = id
				s.added = append(s.added, edge)
			}
		}
		s.rewire(u, id)
	}
}

// reaches reports whether the taint entering v through defs[i] can still be what a use
// reads -- that is, whether some path from that definition to the use avoids every other
// definition of the same value.
//
// Stated as its negation, because that is the direction certainty runs in: defs[i] is
// KILLED for this use when some other definition is unavoidable on the way to it and
// cannot itself be followed by defs[i].
func (s *splitter) reaches(defs []ir.Flow, i int, u use, graph *cfg.Graph) bool {
	for j := range defs {
		if j == i {
			continue
		}
		if dominatesUse(defs[j], u, graph) && !canReach(defs[j], defs[i], graph) {
			return false
		}
	}
	return true
}

// dominatesUse reports whether a definition has definitely already run by the time a use
// executes.
//
// Within one block that is a source-order question, and it is asked by LINE and not by
// column on purpose: `x = f(x)` writes the definition and the read of the old value on
// the same line, and treating the read as coming after the assignment would break the
// chain through every transform written that way.
func dominatesUse(def ir.Flow, u use, graph *cfg.Graph) bool {
	if def.Block == u.block {
		// A block that can reach itself is inside a cycle the graph does model, and
		// source order says nothing there.
		if graph.Reaches(def.Block, def.Block) {
			return false
		}
		return def.Loc.Line < u.loc.Line
	}
	return graph.Dominates(def.Block, u.block)
}

// canReach reports whether control can get from one definition to another, so that the
// second overwrites what the first left behind. Ties in source order count as reachable:
// the uncertain answer is the one that keeps a definition alive.
func canReach(from, to ir.Flow, graph *cfg.Graph) bool {
	if from.Block == to.Block {
		return graph.Reaches(from.Block, from.Block) || from.Loc.Line <= to.Loc.Line
	}
	return graph.Reaches(from.Block, to.Block)
}

// usesOf collects the reads of a value this pass can both position and rewire.
//
// Deliberately not exhaustive. A return, a write into a property, a comparison and a
// value that merely names this one as its base all keep referring to the merged value,
// which is what they did before this pass existed. Missing a use can only leave a
// definition alive; it can never kill one.
func (s *splitter) usesOf(id string) []use {
	var out []use
	for i := range s.fn.Flows {
		f := s.fn.Flows[i]
		if f.From != id || f.Block == "" {
			continue
		}
		out = append(out, use{block: f.Block, loc: f.Loc, flow: i, original: id})
	}
	for i, c := range s.fn.Calls {
		if c.Block == "" {
			continue
		}
		if c.ReceiverID == id {
			out = append(out, use{block: c.Block, loc: c.Loc, call: i, arg: -1, isCall: true, original: id})
		}
		for j, a := range c.Args {
			if a.ValueID == id {
				out = append(out, use{block: c.Block, loc: c.Loc, call: i, arg: j, isCall: true, original: id})
			}
		}
	}
	return out
}

func (s *splitter) rewire(u use, to string) {
	if !u.isCall {
		if s.flowFrom == nil {
			s.flowFrom = make(map[int]string)
		}
		s.flowFrom[u.flow] = to
		return
	}
	if u.arg < 0 {
		if s.receiver == nil {
			s.receiver = make(map[int]string)
		}
		s.receiver[u.call] = to
		return
	}
	if s.callArg == nil {
		s.callArg = make(map[[2]int]string)
	}
	s.callArg[[2]int{u.call, u.arg}] = to
}

// rewritten applies the accumulated rewrites to a copy of the function.
func (s *splitter) rewritten() *ir.Function {
	if len(s.newVals) == 0 {
		return nil
	}

	out := *s.fn
	out.Values = make([]*ir.Value, 0, len(s.fn.Values)+len(s.newVals))
	out.Values = append(out.Values, s.fn.Values...)
	out.Values = append(out.Values, s.newVals...)

	out.Flows = make([]ir.Flow, 0, len(s.fn.Flows)+len(s.added))
	for i, f := range s.fn.Flows {
		if to, ok := s.flowFrom[i]; ok {
			f.From = to
		}
		out.Flows = append(out.Flows, f)
	}
	out.Flows = append(out.Flows, s.added...)

	out.Calls = make([]*ir.Call, len(s.fn.Calls))
	for i, c := range s.fn.Calls {
		_, hasReceiver := s.receiver[i]
		rewritten := hasReceiver
		for j := range c.Args {
			if _, ok := s.callArg[[2]int{i, j}]; ok {
				rewritten = true
			}
		}
		if !rewritten {
			out.Calls[i] = c
			continue
		}
		clone := *c
		if hasReceiver {
			clone.ReceiverID = s.receiver[i]
		}
		clone.Args = make([]ir.Arg, len(c.Args))
		copy(clone.Args, c.Args)
		for j := range clone.Args {
			if to, ok := s.callArg[[2]int{i, j}]; ok {
				clone.Args[j].ValueID = to
			}
		}
		out.Calls[i] = &clone
	}
	return &out
}

func (s *splitter) graph(fn *ir.Function) *cfg.Graph {
	if g, ok := s.graphs[fn.ID]; ok {
		return g
	}
	g := cfg.Build(fn)
	s.graphs[fn.ID] = g
	return g
}
