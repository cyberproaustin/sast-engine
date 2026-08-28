package decision

import (
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

// conjuncts answers one question about one function: what was a comparison AND-ed with.
//
// The frontends already state the operator that a graph cannot recover. `&&` and `and`
// lower to a value named "both" and `||`, `or` and `??` to one named "either", because a
// truthy conjunction means EVERY operand held while a truthy disjunction means only that
// some did. The taint admission analysis reads that name to decide whether a check inside
// a condition really answered yes; this reads the same name to ask what else had to be
// true before a comparison could decide anything.
type conjuncts struct {
	// name is each value's own name, so "both" can be recognised.
	name map[string]string
	// into maps a value to the conjunctions it is an operand of.
	into map[string][]string
	// from maps a conjunction to its operands.
	from map[string][]string
	// cmpValue is the value a comparison EXPRESSION produced, keyed by the comparison's
	// location.
	//
	// Joined by location because that is the only join there is: both frontends emit the
	// relational fact into Function.Comparisons and the expression's value into
	// Function.Values, from the same syntax node and with the same Loc, and neither
	// carries a reference to the other. The column is part of the key -- documenso's
	// verifier has two comparisons on one line.
	cmpValue map[ir.Loc]string
}

func conjunctsOf(fn *ir.Function) *conjuncts {
	c := &conjuncts{
		name:     make(map[string]string, len(fn.Values)),
		into:     map[string][]string{},
		from:     map[string][]string{},
		cmpValue: map[ir.Loc]string{},
	}
	for _, v := range fn.Values {
		c.name[v.ID] = v.Name
		if v.Name == "comparison" {
			c.cmpValue[v.Loc] = v.ID
		}
	}
	for _, f := range fn.Flows {
		if f.Kind != "assign" || c.name[f.To] != "both" {
			continue
		}
		c.into[f.From] = append(c.into[f.From], f.To)
		c.from[f.To] = append(c.from[f.To], f.From)
	}
	return c
}

// operands returns every value that had to hold for this comparison to decide anything:
// the operands of every conjunction the comparison's own result is inside, expanded
// through nested conjunctions.
//
// `a && b && a !== b` parses as `(a && b) && (a !== b)`, so the comparison is an operand
// of the OUTER conjunction and `a` and `b` are operands of the inner one. Walking up from
// the comparison and then back down through the conjunctions found is what puts all three
// in one set; a single hop in either direction reaches half of it.
func (c *conjuncts) operands(cmp ir.Comparison) map[string]bool {
	seed, ok := c.cmpValue[cmp.Loc]
	if !ok {
		return nil
	}
	enclosing := map[string]bool{}
	queue := []string{seed}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, b := range c.into[cur] {
			if enclosing[b] {
				continue
			}
			enclosing[b] = true
			queue = append(queue, b)
		}
	}
	if len(enclosing) == 0 {
		return nil
	}
	out := map[string]bool{}
	queue = queue[:0]
	for b := range enclosing {
		queue = append(queue, b)
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		for _, operand := range c.from[cur] {
			out[operand] = true
			if c.name[operand] == "both" {
				queue = append(queue, operand)
			}
		}
	}
	delete(out, seed)
	return out
}

// skippedByOperandPresence reports whether this comparison is conjoined with a test that
// each of its own operands is PRESENT -- so that a caller who omits one skips whatever
// the comparison decides.
//
//	if (decodedToken.scope && scope && decodedToken.scope !== scope) throw ...
//
// Both spellings of the presence test count, because they are one claim. `a` is truthy
// and `a !== undefined` say the same thing about `a` and differ only in what else they
// admit, and a rule that read one and not the other would be reporting a style.
//
// Read by DENOTATION rather than by value identity. Both frontends give every syntactic
// property read its own value node, so the `decodedToken.scope` in the guard and the
// `decodedToken.scope` in the comparison are two nodes naming one field, and identity
// finds neither of them.
func skippedByOperandPresence(ix *ir.Index, fn *ir.Function, c *conjuncts, cmp ir.Comparison) bool {
	operands := c.operands(cmp)
	if len(operands) == 0 {
		return false
	}
	present := map[string]bool{}
	for id := range operands {
		present[denotation(ix, id)] = true
		if c.name[id] != "comparison" {
			continue
		}
		// A conjunct that is itself a comparison against nothing -- `a !== undefined` --
		// tests the presence of its other side.
		v := ix.ValueByID[id]
		if v == nil {
			continue
		}
		for _, guard := range fn.Comparisons {
			if guard.Loc != v.Loc || !isInequality(guard.Op) {
				continue
			}
			if absentValue(ix.ValueByID[guard.Right]) {
				present[denotation(ix, guard.Left)] = true
			}
			if absentValue(ix.ValueByID[guard.Left]) {
				present[denotation(ix, guard.Right)] = true
			}
		}
	}
	return present[denotation(ix, cmp.Left)] && present[denotation(ix, cmp.Right)]
}

// isInequality reports whether an operator asks whether two values DIFFER, in either
// frontend's spelling. Python names its operators after the AST node.
func isInequality(op string) bool {
	switch op {
	case "!=", "!==", "<>", "NotEq", "IsNot", "is not":
		return true
	}
	return false
}

// denotation names WHAT a value reads rather than which occurrence of it this is.
// `decodedToken.scope` written twice is two values and one field.
//
// Bounded rather than recursive to a fixed point, because the base chain is a syntax tree
// path and a malformed IR must not be able to spin here.
func denotation(ix *ir.Index, id string) string {
	path := ""
	for i := 0; i < 8; i++ {
		v := ix.ValueByID[id]
		if v == nil || v.Kind != ir.ValueProperty || v.Base == "" || v.Path == "" {
			break
		}
		path = v.Path + "\x00" + path
		id = v.Base
	}
	if path == "" {
		return id
	}
	return id + "\x00" + path
}

// rejectsWhenTrue reports whether the side of this branch on which the comparison HELD
// leaves the function by throwing.
//
// The polarity is the whole point. `if (a && b && a !== b) throw` refuses on the side
// where the values differ, so an absent operand skips a REFUSAL; `if (a && b && a !== b)
// update()` does work on that side, and an absent operand skips the work -- which is what
// the guard was written to arrange. Six of the seven occurrences of this shape across ten
// production repositories are the second kind.
//
// Asked as "reachable through successor zero AND through no other successor", rather than
// as a walk forward from that successor. A throw the function performs somewhere else
// entirely is reachable from the taken side too, once the branch rejoins the main line,
// and a walk that stopped at the first one it met would read any function that throws
// anywhere as refusing here.
//
// A throw and not any exit: a `return` is how an ordinary predicate answers, and the
// corpus holds far more of those. A rejection written as a response -- `return c.json({
// error }, 403)` -- is a stated miss for the same reason.
func rejectsWhenTrue(fn *ir.Function, cmp ir.Comparison) bool {
	g := cfg.Build(fn)
	if g == nil {
		return false
	}
	for i := range fn.Blocks {
		b := fn.Blocks[i]
		if b.Terminator != "throw" {
			continue
		}
		if g.SelectedBySuccessor(b.ID, cmp.Block, 0) {
			return true
		}
	}
	return false
}

// namesTheSameThing reports whether the two sides of a comparison were written with the
// same trailing NAME -- `decodedToken.scope` against `scope`.
//
// This is the evidence that one side is the claim and the other is the expectation about
// it, and it is what a reader checks first: a program comparing a token's `scope` with a
// parameter called `scope` has written down which two things it believes should agree.
func namesTheSameThing(ix *ir.Index, left, right string) bool {
	l, r := leafName(ix.ValueByID[left]), leafName(ix.ValueByID[right])
	return l != "" && l == r
}

func leafName(v *ir.Value) string {
	if v == nil {
		return ""
	}
	name := v.Path
	if name == "" {
		name = v.Name
	}
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToLower(name)
}
