// A permission the program selected and then never asked for.
//
// The other rules in this package read a refusal that EXISTS and does not hold: one that
// does not stop what follows it, one abandoned on a branch, one constructed and dropped.
// This reads the case where the refusal was never written at all -- only its ingredients
// were. saleor's `check_metadata_permissions` decodes the object's type out of the global
// id, looks the required permission up in the map that exists for exactly this purpose,
// rejects a type the map does not cover, and returns:
//
//	type_name, db_id = graphene.Node.from_global_id(object_id)
//	if private:
//	    meta_permission = PRIVATE_META_PERMISSION_MAP.get(type_name)
//	else:
//	    meta_permission = PUBLIC_META_PERMISSION_MAP.get(type_name)
//	if not meta_permission:
//	    raise NotImplementedError(f"Couldn't resolve permission to item type: {type_name}. ")
//
// Nothing here is a mistake in itself. The lookup is the right lookup, the map is the
// right map, and the rejection is a real rejection that is properly obeyed -- which is
// why the analyses that read calls, values, decisions and graphs all pass over it. What
// is wrong is what is absent: nobody ever asks whether the CALLER holds the permission
// this found. The function's own name says it checks one.
//
// # What keeps this quiet
//
// Three names have to agree, and they are the program's own words rather than the
// engine's guess. The value has to come out of something named for permissions, it has to
// be BOUND to a name that says permission, and the function it sits in has to be named
// for enforcing rather than for fetching -- `get_permissions` returns permissions as data
// and is not this. Measured over ten production repositories, the shape occurs once.
//
// The existence test is deliberately not a use. That is the whole finding: asking whether
// a lookup returned anything is a question about the MAP, not about the caller. Stating
// it that way also keeps the rule from depending on a frontend gap -- Python's lowering
// records `if private:` as a truthiness comparison and records nothing at all for `if not
// meta_permission:`, and a rule that read "no comparison mentions it" would go silent the
// day that asymmetry is fixed.
package guard

import (
	"fmt"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

func uncheckedControl(ix *ir.Index, fn *ir.Function, g *cfg.Graph,
	up map[string][]*ir.Function, rule model.GuardRule) []taint.Finding {

	shape := rule.Unchecked
	if ix.InTestModule(fn.Loc) || len(fn.Values) == 0 {
		return nil
	}
	// The enclosing function has to be a control. A permission selected inside
	// `get_permission_map` is being RETURNED as data, and its caller is where any
	// question about it would be asked; one selected inside `check_metadata_permissions`
	// was selected in order to be applied here, and the program said so by naming it
	// that way.
	if !says(fn.Name, shape.Enforces) || !says(fn.Name, shape.Controls) {
		return nil
	}

	values := make(map[string]*ir.Value, len(fn.Values))
	for _, v := range fn.Values {
		values[v.ID] = v
	}
	consulted := consultedValues(fn, shape)

	var out []taint.Finding
	reported := map[string]bool{}
	for _, c := range fn.Calls {
		if c.ResultID == "" || c.Block == "" || !g.Reachable(c.Block) {
			continue
		}
		// The producer says what kind of thing came out. A mapping named for permissions
		// read with `.get`, or a call named for resolving one.
		if !says(producerName(values, c), shape.Controls) {
			continue
		}
		// And the program's own name for what it bound the answer to. Either half alone
		// is a guess: these repositories are full of functions that return permissions as
		// data, and full of locals called `role` assigned out of a database column.
		bound := boundName(fn, c.ResultID, values)
		if bound == "" || !says(bound, shape.Controls) {
			continue
		}
		if consultedUnder(fn, bound, c.ResultID, consulted) {
			continue
		}
		if _, anchored := taint.EntryOf(ix, fn); !anchored && entryAbove(ix, up, fn) == "" {
			continue
		}
		if reported[bound] {
			continue
		}
		reported[bound] = true
		out = append(out, uncheckedFinding(ix, fn, g, c, bound, up, rule))
	}
	return out
}

// consultedValues is every value the function does something with OTHER than ask whether
// it exists.
//
// Handed to a call, used as a receiver, returned, written somewhere, folded into another
// value, or compared against something that is not nothing. Each of those is the program
// USING what it found; a truthiness test and a comparison against null are the program
// asking whether the lookup succeeded, which is a question about the mapping.
func consultedValues(fn *ir.Function, shape *model.UncheckedControlGuard) map[string]bool {
	out := map[string]bool{}
	for _, c := range fn.Calls {
		if c.ReceiverID != "" {
			out[c.ReceiverID] = true
		}
		for _, a := range c.Args {
			if a.ValueID != "" {
				out[a.ValueID] = true
			}
		}
	}
	for _, id := range fn.Returns {
		out[id] = true
	}
	for _, w := range fn.Writes {
		for _, id := range []string{w.From, w.Base, w.Key} {
			if id != "" {
				out[id] = true
			}
		}
	}
	// The literals that stand for NOTHING, and only those. `perm == None` asks whether
	// the lookup found one; `perm == "MANAGE_ORDERS"` asks which one it found, and that
	// is a real question about the permission however little the program does with the
	// answer. Both frontends normalise the language's own spelling to `null`, and the
	// empty string is here because a mapping that returns `""` for a type it does not
	// cover is the same test written differently.
	literals := map[string]bool{}
	for _, v := range fn.Values {
		if v.Kind != ir.ValueLiteral {
			continue
		}
		switch strings.ToLower(v.Literal) {
		case "null", "none", "undefined", "":
			literals[v.ID] = true
		}
	}
	for _, cmp := range fn.Comparisons {
		if existenceTest(cmp, literals, shape) {
			continue
		}
		if cmp.Left != "" {
			out[cmp.Left] = true
		}
		if cmp.Right != "" {
			out[cmp.Right] = true
		}
	}
	return out
}

// existenceTest reports whether a comparison asks only whether the value is there.
//
// A truthiness test is one whatever it was written against, because a frontend supplies
// the other operand itself. A relational operator counts only against a literal standing
// for nothing -- `perm == None`, `perm != null`, `perm === undefined` -- since `perm ==
// MANAGE_ORDERS` is a real question about which permission was found.
func existenceTest(cmp ir.Comparison, literals map[string]bool,
	shape *model.UncheckedControlGuard) bool {

	matched := false
	for _, op := range shape.Existence {
		if strings.EqualFold(cmp.Op, op) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	if strings.EqualFold(cmp.Op, "truthy") || strings.EqualFold(cmp.Op, "falsy") {
		return true
	}
	return literals[cmp.Left] || literals[cmp.Right]
}

// consultedUnder asks whether the permission was used, keyed on the NAME the program
// bound it to rather than on the value the lookup produced.
//
// The name is the only identity that survives both frontends, and here it is the only one
// that is even correct. A permission chosen on two branches is two assignments to one
// variable; Python lowers that as two values and TypeScript as one with two edges in, and
// the use below the branch attaches to whichever the frontend left current. Asking about
// the value alone reports the OTHER branch of a function that checks perfectly -- which
// is exactly what `check_metadata_permission_applied` in the fixture is there to catch.
func consultedUnder(fn *ir.Function, name, result string, consulted map[string]bool) bool {
	for _, v := range fn.Values {
		if v.Kind != ir.ValueLocal || v.Name != name {
			continue
		}
		if consulted[v.ID] || anyConsulted(fn, v.ID, consulted) {
			return true
		}
	}
	return consulted[result] || anyConsulted(fn, result, consulted)
}

// anyConsulted follows the assignment chains out of a value, so a permission copied to a
// second name before being used is used.
func anyConsulted(fn *ir.Function, from string, consulted map[string]bool) bool {
	seen := map[string]bool{from: true}
	frontier := []string{from}
	for depth := 0; depth < 8 && len(frontier) > 0; depth++ {
		var next []string
		for _, id := range frontier {
			for _, f := range fn.Flows {
				if f.From != id || seen[f.To] {
					continue
				}
				seen[f.To] = true
				if consulted[f.To] {
					return true
				}
				next = append(next, f.To)
			}
		}
		frontier = next
	}
	return false
}

// producerName is what the value came OUT of: the receiver a method was called on where
// there is one, and the callee otherwise. `PRIVATE_META_PERMISSION_MAP.get(type_name)`
// is a permission because of the map, not because of `get`.
func producerName(values map[string]*ir.Value, c *ir.Call) string {
	if recv := values[c.ReceiverID]; recv != nil {
		if recv.Name != "" {
			return recv.Name
		}
		if recv.Path != "" {
			return recv.Path
		}
	}
	return nameOf(c)
}

// boundName is the name the function gave the result, taken from the assignment out of
// the call. A result nothing was assigned to has no name, and a rule that read the
// program's own words has nothing to read.
func boundName(fn *ir.Function, result string, values map[string]*ir.Value) string {
	for _, f := range fn.Flows {
		if f.From != result {
			continue
		}
		if v := values[f.To]; v != nil && v.Kind == ir.ValueLocal && !syntheticName(v.Name) {
			return v.Name
		}
	}
	return ""
}

// refusalAfter is where the function's only remaining act on the selection sits: the
// branch it reaches once the permission is in hand, on the arm that leaves.
//
// Cited because that is the line a reader has to look at. Standing at the lookup shows a
// correct lookup; standing here shows the whole of what the function does with what it
// found, which is to complain when the MAP has no entry and otherwise to fall out of the
// bottom.
func refusalAfter(fn *ir.Function, g *cfg.Graph, from string) *ir.Block {
	byID := make(map[string]*ir.Block, len(fn.Blocks))
	for i := range fn.Blocks {
		byID[fn.Blocks[i].ID] = &fn.Blocks[i]
	}
	var best *ir.Block
	for i := range fn.Blocks {
		b := &fn.Blocks[i]
		if b.Terminator != "branch" || b.ID == from || !g.Reaches(from, b.ID) {
			continue
		}
		for _, s := range b.Successors {
			arm := byID[s]
			if arm == nil || (arm.Terminator != "throw" && arm.Terminator != "return") {
				continue
			}
			if best == nil || earlierBlock(arm, best) {
				best = arm
			}
		}
	}
	return best
}

func earlierBlock(a, b *ir.Block) bool {
	if a.Loc.Line != b.Loc.Line {
		return a.Loc.Line < b.Loc.Line
	}
	return a.Loc.Column < b.Loc.Column
}

func says(name string, words []string) bool {
	n := letters(name)
	if n == "" {
		return false
	}
	for _, w := range words {
		if strings.Contains(n, letters(w)) {
			return true
		}
	}
	return false
}

func uncheckedFinding(ix *ir.Index, fn *ir.Function, g *cfg.Graph, sel *ir.Call,
	bound string, up map[string][]*ir.Function, rule model.GuardRule) taint.Finding {

	sink := sel.Loc
	hops := []taint.Hop{{
		Loc:         sel.Loc,
		Description: fmt.Sprintf("`%s` is looked up here, in %s()", bound, callName(ix, sel)),
		Resolution:  ir.Resolved,
	}}
	if arm := refusalAfter(fn, g, sel.Block); arm != nil {
		sink = arm.Loc
		hops = append(hops, taint.Hop{
			Loc: arm.Loc,
			Description: fmt.Sprintf(
				"the only question asked about `%s` is whether the lookup found one", bound),
			Resolution: ir.Resolved,
		})
	}
	hops = append(hops, taint.Hop{
		Loc: fn.Loc,
		Description: fmt.Sprintf(
			"%s() returns without asking whether the caller holds `%s`", fn.Name, bound),
		Resolution: ir.Resolved,
	})
	return taint.Finding{
		Analysis:      rule.ID,
		DataClass:     "control-flow",
		ChannelID:     rule.ID,
		Class:         rule.Finding,
		CWE:           rule.CWE,
		Message:       rule.Reason,
		SinkLoc:       sink,
		SinkSymbol:    fn.Name,
		SinkFunction:  fn.Name,
		SinkRational:  rule.Rationale,
		SourceLabel:   bound,
		SourceLoc:     sel.Loc,
		InTestModule:  ix.InTestModule(sel.Loc),
		Path:          hops,
		SinkArgIndex:  -1,
		Confidence:    taint.High,
		EntryAnchored: true,
		EntryPoint:    entryAbove(ix, up, fn),
	}
}
