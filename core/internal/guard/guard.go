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
			for _, c := range fn.Calls {
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

func enclosing(ix *ir.Index, fn *ir.Function) string {
	if ep, ok := ix.EntryByFunc[fn.ID]; ok {
		if m, p := ep.Detail["method"], ep.Detail["path"]; m != "" && p != "" {
			return m + " " + p
		}
	}
	return ""
}
