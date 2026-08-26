// Package surface enumerates an application's attack surface from the IR.
//
// This is the engine's primary output (ADR-009). Findings are assertions over this
// model, not patterns matched against text — which is what makes it possible to state
// that something is MISSING, the class of defect a pattern engine cannot express.
//
// The surface is also the part of a report an operator can audit: if the enumerated
// entry points do not match the application they know, no conclusion drawn from them
// is worth anything, and they can see that immediately.
package surface

import (
	"sort"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/policy"
)

// Control is a security control observed on an entry point, and where it came from.
type Control struct {
	Ref    string // stable identity used to compare peers
	Name   string
	Kind   string // "authentication" | "authorization" | "rate-limit" | "" when unrecognized
	Scope  string // "route" | "app" | "handler-body"
	Origin string // "middleware" | "call"
	Loc    ir.Loc

	// Reach is how many entry points in this application carry this control, and
	// Discriminates is false when that is all of them.
	//
	// A control on every entry point tells you nothing about any particular one. Rate
	// limiting, request logging, CORS and tracing are applied everywhere by design, and
	// on real code they are indistinguishable by name from an authentication guard:
	// every route in one production codebase carries a ThrottlerBehindProxyGuard, so
	// nothing reads as uncontrolled and nothing reads as authenticated.
	//
	// The population answers what the name cannot (ADR-010). This is stated on the
	// surface rather than used to decide anything, because "applied everywhere" is
	// evidence about a control, not a verdict about an entry point.
	Reach         int
	Discriminates bool
}

// EntryFacts is one enumerated entry point and everything known about it.
type EntryFacts struct {
	EntryPoint ir.EntryPoint
	Function   *ir.Function

	// Group is the comparison population for convention analysis (ADR-010).
	Group string

	Method string
	Path   string

	Controls []Control
}

// Loc is where this entry point lives: its handler when resolved, otherwise the
// place it is registered.
func (e EntryFacts) Loc() ir.Loc {
	if e.Function != nil {
		return e.Function.Loc
	}
	return e.EntryPoint.Loc
}

// Label is a human identity for this entry point.
func (e EntryFacts) Label() string {
	if e.Method != "" && e.Path != "" {
		return e.Method + " " + e.Path
	}
	if e.Function != nil {
		return e.Function.Name
	}
	return e.EntryPoint.FunctionID
}

// ControlRefs is the set of control identities on this entry point.
func (e EntryFacts) ControlRefs() map[string]Control {
	out := make(map[string]Control, len(e.Controls))
	for _, c := range e.Controls {
		out[c.Ref] = c
	}
	return out
}

// Surface is the enumerated attack surface.
type Surface struct {
	Entries []EntryFacts
	// Completeness is evidence about whether this enumeration accounts for the program.
	Completeness Completeness
}

// Completeness is what the engine can observe about its own blind spots.
//
// A surface is the primary output and every conclusion rests on it (ADR-009), which makes
// an INCOMPLETE surface the most dangerous thing this engine can produce: it reports
// nothing, and nothing is what a clean application also reports. The two are
// distinguishable, and this is how. A program that reads caller-supplied input in code no
// enumerated entry point can reach is a program whose routes were not all found.
//
// Counted rather than judged. The engine cannot know how many routes an application ought
// to have; it can know that it enumerated none while the program reads request data in a
// hundred and nineteen places, and that is enough to stop a reader trusting the silence.
type Completeness struct {
	// InputFunctions read caller-supplied input.
	InputFunctions int
	// UnreachedInputFunctions read it without any enumerated entry point reaching them.
	UnreachedInputFunctions int
}

// Suspect reports whether the enumeration contradicts what the program plainly does.
func (c Completeness) Suspect(entries int) bool {
	if c.InputFunctions == 0 {
		return false
	}
	// No entry points at all, in a program that reads request data, is a contradiction
	// rather than a judgement call.
	if entries == 0 {
		return true
	}
	// Otherwise: what SHARE of the code that reads request data does the surface fail to
	// account for.
	//
	// This used to compare the unreached count against the number of entry points, which
	// is backwards: it made enumerating MORE routes lower the bar for calling the run
	// complete. jupyterhub proved it. At 9 entry points the engine said INCOMPLETE and
	// refused to report any requirement satisfied; at 114 -- the same application, a
	// surface an adjudicator verified had grown twelvefold and was still missing whole
	// families -- the count slipped under the threshold and the engine went quiet and
	// reported six requirements satisfied. The gate switched off because the surface got
	// bigger, not because it got complete.
	//
	// A ratio cannot do that. Half is the line: if most of the code that reads what a
	// caller sent cannot be reached from anything enumerated, the enumeration does not
	// describe the program, and how many routes happen to be in it is beside the point.
	return c.UnreachedInputFunctions*2 > c.InputFunctions
}

// Groups returns entry points bucketed by comparison population, in stable order.
func (s Surface) Groups() map[string][]EntryFacts {
	out := make(map[string][]EntryFacts)
	for _, e := range s.Entries {
		out[e.Group] = append(out[e.Group], e)
	}
	return out
}

// GroupNames returns group keys in stable order.
func (s Surface) GroupNames() []string {
	seen := make(map[string]bool)
	var names []string
	for _, e := range s.Entries {
		if !seen[e.Group] {
			seen[e.Group] = true
			names = append(names, e.Group)
		}
	}
	sort.Strings(names)
	return names
}

// Build enumerates the surface from a lowered program.
func Build(d *ir.IR, m model.Model, p *policy.Policy) Surface {
	ix := ir.NewIndex(d)
	var entries []EntryFacts

	for _, ep := range d.EntryPoints {
		fn := ix.FuncByID[ep.FunctionID]
		facts := EntryFacts{
			EntryPoint: ep,
			Function:   fn,
			Method:     ep.Detail["method"],
			Path:       ep.Detail["path"],
			Group:      groupOf(ep, fn),
		}
		facts.Controls = controlsOf(ep, fn, m, p)
		entries = append(entries, facts)
	}

	// Reach is a property of the population, so it can only be computed once every
	// entry point has been enumerated.
	reach := map[string]int{}
	for _, e := range entries {
		for ref := range e.ControlRefs() {
			reach[ref]++
		}
	}
	for i := range entries {
		for j := range entries[i].Controls {
			c := &entries[i].Controls[j]
			c.Reach = reach[c.Ref]
			c.Discriminates = c.Reach < len(entries)
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Group != entries[j].Group {
			return entries[i].Group < entries[j].Group
		}
		return entries[i].Label() < entries[j].Label()
	})

	return Surface{Entries: entries, Completeness: completenessOf(ix, m)}
}

// groupOf picks the population an entry point should be compared against. The module
// that registers a route is how applications are actually organized (a router per
// file), which makes it a better peer group than a global bucket.
func groupOf(ep ir.EntryPoint, fn *ir.Function) string {
	module := ""
	if fn != nil {
		module = fn.Module
	}
	// A route whose handler did not resolve still belongs to the file that registers
	// it, which is the peer group a reviewer would compare it against.
	if module == "" {
		module = ep.Detail["module"]
	}
	if module == "" {
		module = "<unknown>"
	}
	return ep.Kind + " in " + module
}

// controlsOf collects every control-like signal attached to an entry point.
//
// Middleware bindings are taken as signals REGARDLESS of what they are named or
// whether the engine recognizes them (ADR-010): convention analysis needs only to
// know that peers share a binding this one lacks. Named control rules add
// classification on top, and in-body detection for controls that are called rather
// than mounted.
func controlsOf(ep ir.EntryPoint, fn *ir.Function, m model.Model, p *policy.Policy) []Control {
	// A team's declaration about its own middleware outranks a built-in name guess.
	classify := func(name string) string {
		if kind := p.ClassifyControl(name); kind != "" {
			return kind
		}
		return m.ClassifyControl(name)
	}

	var out []Control

	for _, mw := range ep.Middleware {
		ref := mw.Ref()
		if ref == "" {
			continue
		}
		out = append(out, Control{
			Ref:    ref,
			Name:   displayName(mw),
			Kind:   classify(displayName(mw)),
			Scope:  mw.Scope,
			Origin: "middleware",
			Loc:    mw.Loc,
		})
	}

	if fn != nil {
		for _, c := range fn.Calls {
			name := c.Method
			if name == "" {
				name = c.Callee.Symbol
			}
			kind := classify(name)
			if kind == "" {
				continue
			}
			out = append(out, Control{
				Ref:    "call:" + name,
				Name:   name,
				Kind:   kind,
				Scope:  "handler-body",
				Origin: "call",
				Loc:    c.Loc,
			})
		}
	}

	return out
}

func displayName(mw ir.MiddlewareRef) string {
	if mw.Name != "" {
		return mw.Name
	}
	return mw.Ref()
}

// completenessOf counts the code that handles caller-supplied input and asks how much of
// it the enumerated surface accounts for.
func completenessOf(ix *ir.Index, m model.Model) Completeness {
	// Which value kinds and which framework globals mean "caller-supplied", according to
	// the model rather than to anything hardcoded here.
	kinds := map[string]bool{}
	globals := map[string]bool{}
	// Paths a request object exposes: "body", "query", "params" and the like. Used here
	// as evidence of HANDLER SHAPE, never to seed taint. A function that reads .body off
	// its own first parameter looks exactly like a request handler whether or not any
	// route pointing at it was recognized, and that is the whole question being asked.
	//
	// Without this the check is blind precisely where it is needed most: frameworks that
	// pass a request object into the handler anchor their rule to an enumerated entry
	// point, so a handler nobody enumerated leaves no trace at all.
	paths := map[string]bool{}
	for _, c := range m.Classifications {
		if c.Class != m.UntrustedClass() {
			continue
		}
		for _, r := range c.Rules {
			switch r.Match {
			case model.MatchValueKind:
				kinds[r.ValueKind] = true
			case model.MatchGlobalProperty:
				globals[r.Symbol] = true
			default:
				for _, p := range r.Paths {
					paths[p] = true
				}
			}
		}
	}

	reachable := ix.ReachableFromEntries()
	var out Completeness
	for _, fn := range ix.IR.Functions {
		params := map[string]bool{}
		for _, p := range fn.Params {
			params[p.ValueID] = true
		}

		reads := false
		for _, v := range fn.Values {
			if kinds[string(v.Kind)] {
				reads = true
				break
			}
			base := ix.ValueByID[v.Base]
			if base != nil && base.Kind == "global" && globals[base.Name] {
				reads = true
				break
			}
			if v.Kind == ir.ValueProperty && params[v.Base] && paths[firstSegment(v.Path)] {
				reads = true
				break
			}
		}
		if !reads {
			continue
		}
		out.InputFunctions++
		if !reachable[fn.ID] {
			out.UnreachedInputFunctions++
		}
	}
	return out
}

// firstSegment is the leading name of a dotted access path: "body.target" -> "body".
func firstSegment(path string) string {
	if i := strings.IndexByte(path, '.'); i >= 0 {
		return path[:i]
	}
	return path
}
