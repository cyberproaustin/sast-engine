// Package callshape finds weaknesses visible in a call's own arguments.
//
// The engine's third analysis kind, and the one a large part of the CWE catalog actually
// needs. A flow analysis asks whether untrusted data reaches somewhere dangerous; a
// convention analysis asks whether an entry point has what its peers have. Neither can
// express `createHash("md5")`, which is weak wherever it is written, with nothing reaching
// it and no caller controlling anything.
//
// Deliberately narrow. It matches a LITERAL argument only. A value computed at runtime is
// not matched and not guessed at, which keeps this kind at the precision that makes it
// worth having: a string "md5" handed to a hash constructor is md5, and there is nothing
// to be wrong about.
package callshape

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// Analyze reports every call whose written arguments make it a defect.
func Analyze(d *ir.IR, m model.Model) []taint.Finding {
	if len(m.CallShapes) == 0 {
		return nil
	}
	ix := ir.NewIndex(d)

	// Skipping calls with no written arguments is worth a great deal on a large program,
	// and it is only sound while every shape needs an argument to look at. A shape that
	// matches the call ITSELF has none -- `tempfile.mktemp()` takes nothing -- so the
	// shortcut has to know whether any such shape exists before it can take it.
	callIsEnough := false
	for _, shape := range m.CallShapes {
		// A shape that reads a literal needs one; a shape that asks where an argument
		// CAME FROM does not, and a call whose arguments are all variables is exactly the
		// case it exists for.
		if shape.Always || shape.ArgFromModuleScope != nil {
			callIsEnough = true
			break
		}
	}

	// Judged once over the whole program, because that is the scope of the question:
	// "does this application anywhere disable the header" has one answer, not one per
	// call site.
	var out []taint.Finding
	for _, fn := range d.Functions {
		for _, c := range fn.Calls {
			if len(c.ArgLiterals) == 0 && !callIsEnough {
				continue
			}
			for _, shape := range m.CallShapes {
				if !targets(shape, c) {
					continue
				}
				if len(shape.ReceiverFromCall) > 0 && !receiverMadeBy(d, c, shape.ReceiverFromCall) {
					continue
				}
				if shape.ArgFromModuleScope != nil {
					if !boundAtModuleScope(ix, c, *shape.ArgFromModuleScope) {
						continue
					}
					out = append(out, finding(ix, fn, c, shape, callName(c)))
					continue
				}
				lit, ok := match(c, shape)
				if !ok {
					continue
				}
				out = append(out, finding(ix, fn, c, shape, lit))
			}
		}
	}
	return out
}

// keyIs compares an option key on its LAST segment, because an option that decides
// something is routinely written inside a named group -- `webPreferences.nodeIntegration`,
// `httpsAgent.rejectUnauthorized`, `cookie.maxAge` -- and the group it sits in is not what
// makes it a decision. The frontend keeps the parent so the nesting stays visible in the
// evidence.
func keyIs(key, want string) bool {
	key = strings.ToLower(key)
	if i := strings.LastIndex(key, "."); i >= 0 {
		key = key[i+1:]
	}
	return key == want
}

// receiverMadeBy reports whether the object a method was called on came out of one of
// these calls, following plain assignments back so that a handle stored in a variable
// still answers the question.
//
//	with tarfile.open(path) as tar:
//	    tar.extractall(dest)      // the receiver is `tar`, and `tar` is a tarfile
func receiverMadeBy(d *ir.IR, c *ir.Call, symbols []string) bool {
	byResult := map[string]*ir.Call{}
	assigned := map[string]string{}
	for _, fn := range d.Functions {
		for _, call := range fn.Calls {
			if call.ResultID != "" {
				byResult[call.ResultID] = call
			}
		}
		for _, f := range fn.Flows {
			if f.Kind == "assign" && f.From != "" && f.To != "" {
				assigned[f.To] = f.From
			}
		}
	}
	id := c.ReceiverID
	for hops := 0; hops < 8 && id != ""; hops++ {
		if made := byResult[id]; made != nil {
			name := made.Callee.Symbol
			for _, want := range symbols {
				if strings.EqualFold(name, want) || strings.EqualFold(lastDot(name), lastDot(want)) {
					return true
				}
			}
			return false
		}
		id = assigned[id]
	}
	return false
}

func lastDot(s string) string {
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// boundAtModuleScope reports whether an argument resolves to a value the module owns --
// computed once when the file loaded, and the same on every call afterwards.
//
// Only a DIRECT reference counts. Following it through assignments would start answering
// a question about the value's history rather than about where it lives, and the two stop
// agreeing as soon as a function copies it into a local.
func boundAtModuleScope(ix *ir.Index, c *ir.Call, index int) bool {
	for _, a := range c.Args {
		if a.Index != index || a.ValueID == "" {
			continue
		}
		owner := ix.OwnerOfValue[a.ValueID]
		return owner != nil && owner.Name == "<module>"
	}
	return false
}

func targets(shape model.CallShape, c *ir.Call) bool {
	if shape.Symbol != "" {
		return c.Callee.Symbol == shape.Symbol
	}
	if shape.Method != "" {
		return c.Method == shape.Method
	}
	return shape.AnyCall
}

// match finds the literal this shape forbids, if the call carries one.
//
// A positional argument is read by index. A negative index means a keyword argument, and
// every one of them is checked rather than the first: Go map iteration is randomized, so
// reading whichever came out first made `requests.get(url, timeout=5, verify=False)`
// report or not report depending on the run. A scanner that answers differently on
// identical input is worse than one that answers wrongly, because the wrong answer can at
// least be investigated.
func match(c *ir.Call, shape model.CallShape) (string, bool) {
	// A qualified shape says nothing at all unless its qualifier holds. Cookie
	// attributes are judged against what the cookie carries, and the name in argument
	// zero is the only evidence of that available at the call.
	for _, q := range shape.Qualifiers {
		if !q.Holds(c.ArgLiterals) {
			return "", false
		}
	}
	if shape.RequiredKeyword != "" {
		return matchAbsent(c, shape)
	}
	// A positional argument that was never supplied. The count of arguments is the whole
	// evidence, so a call the frontend could not count is not judged.
	if shape.MissingArg != nil {
		if c.ArgCount > *shape.MissingArg {
			return "", false
		}
		return callName(c), true
	}
	// A call that is a defect by existing has no argument to look at.
	if shape.Always {
		return callName(c), true
	}
	// A named option rather than a position.
	if shape.Keyword != "" {
		want := strings.ToLower(shape.Keyword)
		for i, lit := range c.ArgLiterals {
			if i >= 0 {
				continue
			}
			key, value, cut := strings.Cut(lit, "=")
			if !cut || !keyIs(key, want) {
				continue
			}
			// The key was read and the value was not written down. An absence rule wants
			// to know the option is set; a rule about its VALUE has nothing to look at.
			if value == ir.UnknownLiteral {
				continue
			}
			if shape.Matches(value) {
				return lit, true
			}
		}
		return "", false
	}
	if shape.ArgIndex >= 0 {
		lit, ok := c.ArgLiterals[shape.ArgIndex]
		if ok && shape.Matches(lit) {
			return lit, true
		}
		return "", false
	}
	// Deterministic: the keys are visited in a fixed order.
	keys := make([]int, 0, len(c.ArgLiterals))
	for i := range c.ArgLiterals {
		if i < 0 {
			keys = append(keys, i)
		}
	}
	sort.Ints(keys)
	for _, k := range keys {
		if lit := c.ArgLiterals[k]; shape.Matches(lit) {
			return lit, true
		}
	}
	return "", false
}

// matchAbsent reports a required option that this call does not set.
//
// The precondition is the whole rule. `res.cookie('jwt', t, getCookieOpts())` sets
// attributes this frontend cannot see, and treating that as absence produced four false
// positives in a single production file the first time it was tried. So absence is
// claimed only where the keys were actually enumerated, or where no options were passed
// at all -- which is the one case where "it does not set this" is simply true.
func matchAbsent(c *ir.Call, shape model.CallShape) (string, bool) {
	// Further arguments whose keys must also have been read. A payload built by another
	// function says nothing about whether it contains an expiry.
	for _, idx := range shape.AlsoEnumerated {
		if !c.OptionsEnumerated(idx) {
			return "", false
		}
	}
	knowable := c.OptionsEnumerated(shape.OptionsArg)
	if shape.OptionsArg >= 0 && !c.HasArg(shape.OptionsArg) {
		// A rule that needs the options written down says nothing about a call that has
		// none: the setting may live somewhere else in that call entirely.
		if shape.OptionsMustBeWritten {
			return "", false
		}
		knowable = true
	}
	if !knowable {
		return "", false
	}

	// One key names the rule; a widened rule accepts any of several spellings of the
	// same decision, and the absence is only claimed when none of them is there.
	wanted := shape.RequiredAnyOf
	if len(wanted) == 0 {
		wanted = []string{shape.RequiredKeyword}
	}
	for i, lit := range c.ArgLiterals {
		if i >= 0 {
			continue
		}
		key, _, ok := strings.Cut(lit, "=")
		if !ok {
			continue
		}
		for _, want := range wanted {
			if keyIs(key, strings.ToLower(want)) {
				return "", false
			}
		}
	}
	return "no " + shape.RequiredKeyword, true
}

// callName is how a call is named when the finding is about the call itself rather than
// about anything passed to it.
func callName(c *ir.Call) string {
	if c.Callee.Symbol != "" {
		return c.Callee.Symbol + "()"
	}
	return c.Method + "()"
}

func finding(ix *ir.Index, fn *ir.Function, c *ir.Call, shape model.CallShape, lit string) taint.Finding {
	name := c.Callee.Symbol
	if name == "" {
		name = c.Method
	}

	return taint.Finding{
		Analysis:     shape.ID,
		DataClass:    "written-argument",
		ChannelID:    shape.ID,
		Class:        shape.Finding,
		CWE:          shape.CWE,
		Message:      shape.Reason,
		SinkLoc:      c.Loc,
		SinkSymbol:   name,
		SinkArgIndex: shape.ArgIndex,
		InTestModule: ix.InTestModule(c.Loc),
		SinkFunction: fn.Name,
		SinkRational: shape.Rationale,
		SourceLabel:  strconv.Quote(lit),
		SourceLoc:    c.Loc,
		// The evidence is the call itself: this symbol was written with this argument.
		// Short, and complete for the claim being made (ADR-006) -- unlike a flow, there
		// is no path to walk because nothing travelled.
		Path: []taint.Hop{{
			Loc:         c.Loc,
			Description: fmt.Sprintf("%s() is called with %s", name, strconv.Quote(lit)),
			Resolution:  c.Callee.Resolution,
		}},
		// Written into the source, so the call graph has nothing to be uncertain about.
		// Confidence says how well resolution went, not how much the finding matters.
		Confidence: taint.High,
		// Whether this is a defect turns on what the result is used for, which the call
		// does not carry. Reported, never gating, and the report says why.
		DependsOnUse: shape.DependsOnUse,
		// Not an assertion over the enumerated surface (ADR-009 governs flows): a weak
		// hash in a file nothing routes to is still a weak hash. Marked anchored so that
		// it is counted and can gate, with the entry point named where one reaches it.
		EntryAnchored: true,
		EntryPoint:    enclosing(ix, fn),
	}
}

func enclosing(ix *ir.Index, fn *ir.Function) string {
	if ep, ok := ix.EntryByFunc[fn.ID]; ok {
		if m, p := ep.Detail["method"], ep.Detail["path"]; m != "" && p != "" {
			return m + " " + p
		}
	}
	return fn.Name + "()"
}
