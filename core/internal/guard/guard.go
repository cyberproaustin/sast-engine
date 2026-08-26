// Package guard finds a rejection the program wrote and then walked past.
//
// The engine's seventh analysis kind, and the one that reads the SHAPE OF THE GRAPH
// rather than a call, a value or a comparison. A rule here asks a question none of the
// others can state: not what this call does, but whether what follows it can still happen.
//
//	if (!req.body.name) {
//	  res.status(400).json({ error: "name required" })   // no return
//	}
//	createUser(req.body.name)                            // runs anyway
//
// Nothing is wrong with either line. The status is the right status and the creation is
// the right creation; what is wrong is that both of them run. A rule that reads calls
// sees two correct calls, and a rule that reads position sees a check before an
// operation, which is what correct code looks like too.
//
// This kind needs no declared expectation, and that is the whole reason it is worth
// having. The PROGRAM wrote the rejection: it has already said, in its own code, that
// this request should not proceed. The only question left is whether it does -- and that
// is a fact about the control-flow graph, which the frontends already supply.
package guard

import (
	"fmt"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// Analyze reports every rejection the handler did not stop for.
func Analyze(d *ir.IR, m model.Model) []taint.Finding {
	if len(m.Guards) == 0 {
		return nil
	}
	ix := ir.NewIndex(d)
	stops := neverReturns(d)

	var out []taint.Finding
	for _, fn := range d.Functions {
		g := cfg.Build(fn)
		if g == nil {
			continue
		}
		// Blocks that end the request whatever the graph says, because something in them
		// raises. A frontend marks the call when the language declares it -- TypeScript's
		// `never` is exactly this fact -- and the rest are found here, by noticing that
		// every way out of a function is a throw.
		terminal := map[string]bool{}
		for _, c := range fn.Calls {
			if c.Block != "" && endsRequest(c, stops, m) {
				terminal[c.Block] = true
			}
		}

		for _, rule := range m.Guards {
			if len(rule.Constructs) > 0 {
				out = append(out, discardedConstruction(ix, fn, rule)...)
				continue
			}
			for _, c := range fn.Calls {
				if len(rule.Repeats) > 0 {
					out = append(out, repeatingCallback(ix, fn, c, rule)...)
					continue
				}
				if c.Block == "" || terminal[c.Block] || !rejects(c, rule) {
					continue
				}
				after, ok := workAfter(fn, g, c.Block)
				if !ok {
					continue
				}
				out = append(out, finding(ix, fn, c, rule, after))
			}
		}
	}
	return out
}

// repeatingCallback reports a refusal written inside a listener the source will call
// again.
//
// The rejection rule above asks whether work FOLLOWS a refusal. This asks the same thing
// about a callback: not what runs after the refusal, but whether the thing that produced
// the input will be asked for more -- and inside a listener the answer is yes by
// construction, because a `return` ends this invocation and detaches nothing.
//
// Four facts have to hold together and each one removes a population of ordinary code.
// The event has to be one that happens more than once, because `end` and `error` happen
// once and need no detaching. The callback has to APPEND to something it did not create,
// because a callback that keeps nothing costs nothing to run again. There has to be a
// refusal in it, which is the program saying in its own code that this input should stop.
// And nothing may detach the listener or stop the source anywhere near it, which is the
// thing that would have made the refusal real.
func repeatingCallback(ix *ir.Index, fn *ir.Function, c *ir.Call, rule model.GuardRule) []taint.Finding {
	if !matchesName(lastSegment(c.Callee.Symbol), c.Method, rule.Attaches) {
		return nil
	}
	if !namesEvent(c, rule.Repeats) {
		return nil
	}
	cb := callbackOf(ix, c)
	if cb == nil {
		return nil
	}
	// Said here rather than left to be filtered downstream, where it would still be
	// counted: a fixture that reads a stream is not an attack surface.
	if ix.InTestModule(c.Loc) {
		return nil
	}
	// A collection the callback did not make. `chunks.push(chunk)` on an array bound in
	// the enclosing scope is what makes running this again cost memory; the same call on
	// a local made in the callback costs nothing that outlasts the invocation.
	if !accumulatesOutward(ix, cb, rule) {
		return nil
	}
	// Generous in both directions on purpose: a rule reporting the ABSENCE of a call has
	// to be quiet whenever there is any reason to be, so a detach written in the callback,
	// in any of the OTHER listeners registered beside it, or in the function that
	// registered them all, counts.
	if detaches(ix, fn, rule) || detaches(ix, cb, rule) {
		return nil
	}
	var out []taint.Finding
	for _, r := range cb.Calls {
		// Matched on what the call was WRITTEN as, because the promise executor's
		// `reject` is a parameter and resolves to nothing at all. A symbol is a claim
		// about what a name refers to; here the name is the whole evidence.
		if !matchesName(lastSegment(r.Callee.Name), r.Method, rule.Refuses) {
			continue
		}
		out = append(out, repeatFinding(ix, fn, cb, c, r, rule))
	}
	return out
}

// discardedConstruction reports a response the program built and then let fall, where a
// branch beside it returns the identical construction.
//
// The comparison is what makes this sayable. A rule that reported every constructor whose
// result goes nowhere would be reporting dead code, and an engine has no standing to say
// which line of dead code was MEANT to matter. Here it does not have to guess: the same
// call, in the same function, is returned somewhere else, so the program itself has
// written down what this branch was supposed to end with.
//
// Nothing about a status, a name or a keyword is read. Two calls to one constructor,
// one kept and one dropped, is the whole of the evidence.
func discardedConstruction(ix *ir.Index, fn *ir.Function, rule model.GuardRule) []taint.Finding {
	var built []*ir.Call
	for _, c := range fn.Calls {
		if c.ResultID != "" && matchesName(lastSegment(c.Callee.Symbol), c.Method, rule.Constructs) {
			built = append(built, c)
		}
	}
	if len(built) < 2 {
		return nil
	}
	used := consumedValues(fn)
	// The branch that keeps what it built, per constructor. Two constructors used
	// differently in one function say nothing about each other -- a `jsonify` that is
	// returned is not evidence about a `redirect` that is not -- so the sibling has to be
	// a call to the SAME one.
	kept := map[string]*ir.Call{}
	for _, c := range built {
		if used[c.ResultID] {
			name := strings.ToLower(lastSegment(c.Callee.Symbol))
			if _, seen := kept[name]; !seen {
				kept[name] = c
			}
		}
	}

	var out []taint.Finding
	for _, c := range built {
		if used[c.ResultID] {
			continue
		}
		sibling, ok := kept[strings.ToLower(lastSegment(c.Callee.Symbol))]
		if !ok {
			continue
		}
		out = append(out, discardFinding(ix, fn, c, sibling, rule))
	}
	return out
}

// consumedValues is every value the function does something with. A value absent from it
// was produced and then referred to by nothing at all, which in a language without
// destructors is the same as not having been produced.
//
// Written as a census of the whole function rather than as a walk from the value, because
// the question is negative: to say a result is used NOWHERE, nowhere is what has to be
// looked at.
func consumedValues(fn *ir.Function) map[string]bool {
	used := make(map[string]bool, len(fn.Values))
	for _, id := range fn.Returns {
		used[id] = true
	}
	for _, c := range fn.Calls {
		used[c.ReceiverID] = true
		for _, a := range c.Args {
			used[a.ValueID] = true
		}
	}
	for _, f := range fn.Flows {
		used[f.From], used[f.To] = true, true
	}
	for _, cmp := range fn.Comparisons {
		used[cmp.Left], used[cmp.Right] = true, true
	}
	for _, w := range fn.Writes {
		used[w.From], used[w.Base] = true, true
	}
	// A property read off a value is a use of the value it was read off.
	for _, v := range fn.Values {
		if v.Base != "" {
			used[v.Base] = true
		}
	}
	delete(used, "")
	return used
}

func discardFinding(ix *ir.Index, fn *ir.Function, dropped, kept *ir.Call, rule model.GuardRule) taint.Finding {
	name := callName(ix, dropped)
	return taint.Finding{
		Analysis:     rule.ID,
		DataClass:    "control-flow",
		ChannelID:    rule.ID,
		Class:        rule.Finding,
		CWE:          rule.CWE,
		Message:      rule.Reason,
		SinkLoc:      dropped.Loc,
		SinkSymbol:   name,
		SinkFunction: fn.Name,
		SinkRational: rule.Rationale,
		SourceLabel:  name,
		SourceLoc:    kept.Loc,
		InTestModule: ix.InTestModule(dropped.Loc),
		Path: []taint.Hop{
			{Loc: kept.Loc, Description: fmt.Sprintf("%s() is built and returned here, which is the shape this program uses to refuse", name), Resolution: ir.Resolved},
			{Loc: dropped.Loc, Description: fmt.Sprintf("%s() is built here and used by nothing, so the branch falls through", name), Resolution: ir.Resolved},
		},
		Confidence:    taint.High,
		EntryAnchored: true,
		EntryPoint:    entryAbove(ix, parents(ix), fn),
	}
}

// namesEvent reports whether a registration named one of these events. The name is the
// only thing that says whether a callback is called again, and it is written at the call.
func namesEvent(c *ir.Call, events []string) bool {
	lit, ok := c.ArgLiterals[0]
	if !ok {
		return false
	}
	for _, want := range events {
		if strings.EqualFold(strings.TrimSpace(lit), want) {
			return true
		}
	}
	return false
}

// callbackOf is the function a registration was handed.
func callbackOf(ix *ir.Index, c *ir.Call) *ir.Function {
	for _, a := range c.Args {
		if a.FunctionID != "" {
			return ix.FuncByID[a.FunctionID]
		}
	}
	return nil
}

// accumulatesOutward reports whether the callback adds to a collection that outlasts the
// invocation -- one whose binding belongs to some other function.
func accumulatesOutward(ix *ir.Index, cb *ir.Function, rule model.GuardRule) bool {
	for _, c := range cb.Calls {
		if !matchesName(lastSegment(c.Callee.Symbol), c.Method, rule.Accumulates) {
			continue
		}
		if c.ReceiverID == "" {
			continue
		}
		if owner := ix.OwnerOfValue[c.ReceiverID]; owner != nil && owner.ID != cb.ID {
			return true
		}
	}
	return false
}

// detaches reports whether a function anywhere in it removes the listener or stops what
// feeds it.
func detaches(ix *ir.Index, fn *ir.Function, rule model.GuardRule) bool {
	for _, c := range fn.Calls {
		if matchesName(lastSegment(c.Callee.Symbol), c.Method, rule.Detaches) ||
			matchesName(lastSegment(c.Callee.Name), c.Method, rule.Detaches) {
			return true
		}
		// The listeners registered beside this one are lowered as separate functions, and
		// a `destroy` in the error handler is a destroy.
		if cb := callbackOf(ix, c); cb != nil && cb.ID != fn.ID {
			for _, inner := range cb.Calls {
				if matchesName(lastSegment(inner.Callee.Symbol), inner.Method, rule.Detaches) ||
					matchesName(lastSegment(inner.Callee.Name), inner.Method, rule.Detaches) {
					return true
				}
			}
		}
	}
	return false
}

func repeatFinding(ix *ir.Index, fn *ir.Function, cb *ir.Function, attach, refuse *ir.Call,
	rule model.GuardRule) taint.Finding {
	event := attach.ArgLiterals[0]
	name := callName(ix, refuse)
	if name == "the work it was refusing" && refuse.Callee.Name != "" {
		name = refuse.Callee.Name
	}
	return taint.Finding{
		Analysis:     rule.ID,
		DataClass:    "control-flow",
		ChannelID:    rule.ID,
		Class:        rule.Finding,
		CWE:          rule.CWE,
		Message:      rule.Reason,
		SinkLoc:      refuse.Loc,
		SinkSymbol:   name,
		SinkFunction: cb.Name,
		SinkRational: rule.Rationale,
		SourceLabel:  event,
		SourceLoc:    attach.Loc,
		InTestModule: ix.InTestModule(refuse.Loc),
		Path: []taint.Hop{
			{Loc: attach.Loc, Description: fmt.Sprintf("a callback is registered for %q, which happens again", event), Resolution: ir.Resolved},
			{Loc: refuse.Loc, Description: fmt.Sprintf("%s() refuses, and nothing detaches the callback or stops the source", name), Resolution: ir.Resolved},
		},
		Confidence:    taint.High,
		EntryAnchored: true,
		EntryPoint:    entryAbove(ix, parents(ix), fn),
		SinkArgIndex:  -1,
	}
}

// workAfter reports whether anything UNAVOIDABLE after this block still calls something,
// and names the first such call.
//
// This is the whole judgement, and asking it this way is what separates the two shapes
// that look alike. `if (bad) { reject } else { work }` reconverges on an empty block:
// everything happened inside the branches, and there is nothing after. `if (bad) { reject }
// work` reconverges on the work itself.
func workAfter(fn *ir.Function, g *cfg.Graph, block string) (*ir.Call, bool) {
	var best *ir.Call
	for _, b := range fn.Blocks {
		if b.ID == block || !g.PostDominates(b.ID, block) {
			continue
		}
		for _, c := range fn.Calls {
			if c.Block != b.ID {
				continue
			}
			if best == nil || before(c.Loc, best.Loc) {
				best = c
			}
		}
	}
	return best, best != nil
}

func before(a, b ir.Loc) bool {
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	return a.Column < b.Column
}

// rejects reports whether a call writes a refusal into the response.
func rejects(c *ir.Call, rule model.GuardRule) bool {
	if !matchesName(lastSegment(c.Callee.Symbol), c.Method, rule.RejectMethod) {
		return false
	}
	for _, lit := range c.ArgLiterals {
		for _, want := range rule.RejectStatus {
			if strings.HasPrefix(lit, want) && len(lit) == 3 {
				return true
			}
		}
	}
	return false
}

// endsRequest reports whether a call does not come back.
//
// `next(err)` is the case that is not obvious. Passing an error to the continuation HANDS
// THE REQUEST OFF: the error middleware answers it, and nothing after this line decides
// anything. `next()` with no argument is the opposite -- it carries on down the chain --
// and one deliberately vulnerable application contains both, four lines apart. The
// argument is the whole difference and there is nothing else to read.
func endsRequest(c *ir.Call, stops map[string]bool, m model.Model) bool {
	if c.Callee.FunctionID != "" && stops[c.Callee.FunctionID] {
		return true
	}
	if isDelegation(c) {
		return true
	}
	for _, rule := range m.Guards {
		if matchesName(lastSegment(c.Callee.Symbol), c.Method, rule.Raises) {
			return true
		}
	}
	return false
}

// isDelegation reports whether a call hands the request to somebody else to answer.
func isDelegation(c *ir.Call) bool {
	name := lastSegment(c.Callee.Symbol)
	if name == "" {
		name = c.Method
	}
	if name == "" {
		// An unresolved call, which is what `next` is: a parameter of the handler, so
		// there is nothing for the frontend to resolve it to. The NAME is still written
		// down, and here it is the whole of the evidence.
		name = c.Callee.Name
	}
	switch strings.ToLower(name) {
	case "next", "reject", "done", "fail":
		return len(c.Args) > 0
	}
	return false
}

// neverReturns finds the local functions every way out of which is a throw.
//
// A helper named `forbidden` or `fail` ends the request as surely as a return does, and
// the caller cannot tell from the call site. The function itself can: if every block it
// leaves from throws, calling it never comes back.
func neverReturns(d *ir.IR) map[string]bool {
	out := map[string]bool{}
	for _, fn := range d.Functions {
		exits, throws := 0, 0
		for _, b := range fn.Blocks {
			if len(b.Successors) != 0 {
				continue
			}
			exits++
			if b.Terminator == "throw" {
				throws++
			}
		}
		if exits > 0 && exits == throws {
			out[fn.ID] = true
		}
	}
	return out
}

func matchesName(symbol, method string, want []string) bool {
	for _, w := range want {
		if strings.EqualFold(symbol, w) || strings.EqualFold(method, w) {
			return true
		}
	}
	return false
}

func lastSegment(s string) string {
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func finding(ix *ir.Index, fn *ir.Function, c *ir.Call, rule model.GuardRule, after *ir.Call) taint.Finding {
	name := c.Callee.Symbol
	if name == "" {
		name = c.Method
	}
	return taint.Finding{
		Analysis:     rule.ID,
		DataClass:    "control-flow",
		ChannelID:    rule.ID,
		Class:        rule.Finding,
		CWE:          rule.CWE,
		Message:      rule.Reason,
		SinkLoc:      c.Loc,
		SinkSymbol:   name,
		SinkFunction: fn.Name,
		SinkRational: rule.Rationale,
		SourceLabel:  callName(ix, after),
		SourceLoc:    after.Loc,
		InTestModule: ix.InTestModule(c.Loc),
		Path: []taint.Hop{
			{Loc: c.Loc, Description: fmt.Sprintf("%s() refuses the request", name), Resolution: ir.Resolved},
			{Loc: after.Loc, Description: fmt.Sprintf("%s() runs anyway", callName(ix, after)), Resolution: ir.Resolved},
		},
		Confidence:    taint.High,
		EntryAnchored: true,
		EntryPoint:    enclosing(ix, fn),
	}
}

func callName(ix *ir.Index, c *ir.Call) string {
	if c.Callee.Symbol != "" {
		return c.Callee.Symbol
	}
	if c.Method != "" {
		return c.Method
	}
	// A local call carries no symbol, so the name is on the function it resolved to.
	if fn := ix.FuncByID[c.Callee.FunctionID]; fn != nil && fn.Name != "" {
		return fn.Name
	}
	return "the work it was refusing"
}

// parents is every function that names this one -- by calling it, or by handing it to
// something else as an argument. A promise executor is reached the second way and no
// other, so a call graph alone loses the entry point above it entirely.
func parents(ix *ir.Index) map[string][]*ir.Function {
	out := make(map[string][]*ir.Function)
	for _, fn := range ix.IR.Functions {
		for _, c := range fn.Calls {
			if c.Callee.FunctionID != "" {
				out[c.Callee.FunctionID] = append(out[c.Callee.FunctionID], fn)
			}
			for _, a := range c.Args {
				if a.FunctionID != "" {
					out[a.FunctionID] = append(out[a.FunctionID], fn)
				}
			}
		}
	}
	return out
}

// entryAbove is the entry point a function runs under, found by ascending a few hops.
//
// Bounded for the same reason the store analysis bounds its own ascent: past a few calls
// the answer stops being evidence that this line runs per-request and starts being
// evidence that the program is connected.
func entryAbove(ix *ir.Index, up map[string][]*ir.Function, fn *ir.Function) string {
	seen := map[string]bool{}
	frontier := []*ir.Function{fn}
	for depth := 0; depth < 4 && len(frontier) > 0; depth++ {
		var next []*ir.Function
		for _, f := range frontier {
			if seen[f.ID] {
				continue
			}
			seen[f.ID] = true
			if name := enclosing(ix, f); name != "" {
				return name
			}
			next = append(next, up[f.ID]...)
		}
		frontier = next
	}
	return ""
}

func enclosing(ix *ir.Index, fn *ir.Function) string {
	if ep, ok := ix.EntryByFunc[fn.ID]; ok {
		if m, p := ep.Detail["method"], ep.Detail["path"]; m != "" && p != "" {
			return m + " " + p
		}
	}
	return ""
}
