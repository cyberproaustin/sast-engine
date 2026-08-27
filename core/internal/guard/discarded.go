// A restriction the program built and then left behind.
//
// The rule beside this one reads a hole in a control's coverage from the operation end: an
// operation reachable by a path the check does not stand on. This reads the same hole from
// the other end -- the control's APPLICATION is not reachable from a path the control was
// already being built on:
//
//	for (const policy of accessPolicy.resource) {
//	  ...
//	  expressions.push(new Condition('compartments', ...));            // built
//	  if (!policy.criteria.startsWith(policy.resourceType + '?')) {
//	    getLogger().warn('Invalid access policy criteria', { ... });
//	    return;                                                        // and abandoned
//	  }
//	}
//	if (expressions.length > 0) {
//	  builder.predicate.expressions.push(new Disjunction(expressions)); // never reached
//	}
//
// The function's only product is the restriction it attaches, so leaving without attaching
// it does not narrow the query -- it widens it. The program noticed its own configuration
// was malformed and answered by removing a restriction, which is failing open.
//
// # What keeps this quiet
//
// A bare early return is NOT reported, and the reason is nine lines below the measured one
// in medplum's own function: `else { return; }` on the no-criteria branch abandons the
// same accumulator and is correct -- a policy naming no criteria allows everything, so a
// disjunction with an already-satisfied term is rightly dropped. Nothing in the graph
// separates those two returns. What separates them is that one of them COMPLAINS first: a
// diagnostic in the exiting block is the program recording that something is wrong, and a
// control that gets weaker on the branch where something is wrong is the weakness. Without
// that condition this rule reports both returns of that one function and is right about
// half of them.
package guard

import (
	"fmt"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

func discardedRestriction(ix *ir.Index, fn *ir.Function, g *cfg.Graph, rule model.GuardRule) []taint.Finding {
	shape := rule.Discards
	// A function that RETURNS something has a product other than its effect, and an early
	// return from one is answering its caller rather than abandoning its work.
	if ix.InTestModule(fn.Loc) || len(fn.Returns) > 0 || len(fn.Blocks) == 0 {
		return nil
	}
	local := map[string]string{}
	for _, v := range fn.Values {
		if v.Kind == ir.ValueLocal && !syntheticName(v.Name) {
			local[v.ID] = v.Name
		}
	}
	if len(local) == 0 {
		return nil
	}

	// Blocks that leave the function by returning, and what the program said on the way
	// out. A throw is deliberately not one of these: raising propagates the refusal, so
	// the caller's query is never built at all and nothing is left open.
	type exit struct {
		block string
		loc   ir.Loc
		said  *ir.Call
	}
	var exits []exit
	for _, b := range fn.Blocks {
		if len(b.Successors) != 0 || b.Terminator != "return" || !g.Reachable(b.ID) {
			continue
		}
		for _, c := range fn.Calls {
			if c.Block == b.ID && complains(nameOf(c), shape) {
				exits = append(exits, exit{block: b.ID, loc: b.Loc, said: c})
				break
			}
		}
	}
	if len(exits) == 0 {
		return nil
	}

	var out []taint.Finding
	seen := map[string]bool{}
	for _, add := range fn.Calls {
		name, ok := local[add.ReceiverID]
		if !ok || add.Block == "" || !g.Reachable(add.Block) {
			continue
		}
		if !matchesName(lastSegment(nameOf(add)), add.Method, shape.Appends) {
			continue
		}
		// A restriction, said by the program rather than guessed at. The engine cannot
		// know what an array of things is FOR; the function that builds it and the name it
		// is built under are the only statements of intent the program contains, and a
		// rule that read neither would report every accumulator in every codebase.
		if !restricts(fn.Name, shape) && !restricts(name, shape) {
			continue
		}
		apply := applicationOf(fn, g, add)
		if apply == nil {
			continue
		}
		for _, e := range exits {
			if e.block == apply.Block || e.block == add.Block || seen[e.block] {
				continue
			}
			// The abandoned path leaves AFTER something was added and BEFORE the point
			// that attaches it, which is what makes the restriction lost rather than
			// merely unused.
			if !g.Reaches(add.Block, e.block) || !g.Reaches(add.Block, apply.Block) {
				continue
			}
			if _, anchored := taint.EntryOf(ix, fn); !anchored {
				continue
			}
			seen[e.block] = true
			out = append(out, discardedFinding(ix, fn, add, apply, e.said, e.loc, name, rule))
		}
	}
	return out
}

// applicationOf is where the collection stops being built and starts being used: handed to
// something as an argument rather than added to.
func applicationOf(fn *ir.Function, g *cfg.Graph, add *ir.Call) *ir.Call {
	var apply *ir.Call
	for _, c := range fn.Calls {
		if c.Block == "" || !g.Reachable(c.Block) || c.ReceiverID == add.ReceiverID {
			continue
		}
		used := false
		for _, a := range c.Args {
			if a.ValueID == add.ReceiverID {
				used = true
				break
			}
		}
		if !used {
			continue
		}
		if apply == nil || earlier(c, apply) {
			apply = c
		}
	}
	return apply
}

func complains(name string, shape *model.DiscardedRestrictionGuard) bool {
	leaf := letters(lastSegment(name))
	for _, w := range shape.Records {
		if strings.HasPrefix(leaf, w) {
			return true
		}
	}
	return false
}

func restricts(name string, shape *model.DiscardedRestrictionGuard) bool {
	n := letters(name)
	for _, w := range shape.Restricts {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

func discardedFinding(ix *ir.Index, fn *ir.Function, add, apply, said *ir.Call,
	exitLoc ir.Loc, collection string, rule model.GuardRule) taint.Finding {
	return taint.Finding{
		Analysis:     rule.ID,
		DataClass:    "control-flow",
		ChannelID:    rule.ID,
		Class:        rule.Finding,
		CWE:          rule.CWE,
		Message:      rule.Reason,
		SinkLoc:      said.Loc,
		SinkSymbol:   callName(ix, said),
		SinkFunction: fn.Name,
		SinkRational: rule.Rationale,
		SourceLabel:  collection,
		SourceLoc:    add.Loc,
		InTestModule: ix.InTestModule(said.Loc),
		Path: []taint.Hop{
			{Loc: add.Loc, Description: fmt.Sprintf("a restriction is added to `%s`", collection), Resolution: ir.Resolved},
			{Loc: said.Loc, Description: "this branch records that the input is wrong, and returns", Resolution: ir.Resolved},
			{Loc: exitLoc, Description: fmt.Sprintf("so `%s` is abandoned here", collection), Resolution: ir.Resolved},
			{Loc: apply.Loc, Description: fmt.Sprintf("and %s(), the only thing that applies it, never runs", callName(ix, apply)), Resolution: ir.Resolved},
		},
		SinkArgIndex:  -1,
		Confidence:    taint.High,
		EntryAnchored: true,
		EntryPoint:    entryAbove(ix, parents(ix), fn),
	}
}
