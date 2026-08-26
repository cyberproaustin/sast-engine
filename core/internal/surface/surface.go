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
	"strconv"
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
	Provenance ir.Provenance

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

// TrustLevel is who can cause this entry point to run. A route answers a stranger; a
// cron job answers a clock. Read from the entry point rather than copied onto these
// facts, so there is one answer and not two.
func (e EntryFacts) TrustLevel() ir.Trust { return e.EntryPoint.TrustLevel() }

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
	// NonApplicationEntries are real registrations the application does not serve:
	// examples, checked-in dependencies, build and development tooling. They remain
	// auditable without being presented as the application's own attack surface.
	NonApplicationEntries []EntryFacts
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
	// NonProductionInputFunctions read it in modules that cannot serve a request --
	// tests, examples, checked-in dependencies. They are not counted above and the
	// number is stated because it is usually the larger one: 733 of healthchecks'
	// 824 input-reading functions are in its test suite, and a count that included
	// them said 745 of 824 unreached about an enumeration an adjudicator had just
	// verified was complete.
	NonProductionInputFunctions int
	// Unreached says WHY the functions counted above cannot be reached, in bounded
	// form.
	//
	// A number without this is not actionable and, worse, is not checkable: a reader
	// who cannot tell "745, and 733 of them are test fixtures" from "745, all of them
	// in views.py" learns to ignore the line, and then it is worth less than nothing
	// on the run where it is right.
	Unreached []UnreachedGroup
}

// UnreachedGroup is one reason a set of input-reading functions is unreachable, with
// enough of them named to check the claim.
type UnreachedGroup struct {
	// Cause is one of the Cause* constants.
	Cause string
	Count int
	// FromReachedCode counts, for CauseMissingCallEdge, the functions whose name is
	// written at a call site the surface DOES reach. Those are the actionable ones:
	// the route was enumerated, the call was found, and only the edge between them
	// is missing.
	FromReachedCode int
	// Modules are the directories holding these functions, largest first, bounded.
	Modules []ModuleCount
	// Sample names a few of them so the cause can be checked rather than believed.
	Sample []UnreachedFunction
}

// ModuleCount is how many unreached functions one directory holds.
type ModuleCount struct {
	Dir   string
	Count int
}

// UnreachedFunction is one named example.
type UnreachedFunction struct {
	Name string
	Loc  ir.Loc
	// Detail is what is known about this one beyond its cause: the caller it sits
	// below, or the property read that made it count as input-reading.
	Detail string
}

// Why an input-reading function is not reachable from any enumerated entry point.
// These are properties of the CALL GRAPH, which is the only thing that can be
// observed here -- the engine cannot know that Django calls a form's clean_ hooks,
// only that nothing in the program does.
const (
	// CauseMissingCallEdge: a call written with this function's name is somewhere in
	// the program and did not resolve to it. The enumeration is not what failed; the
	// call graph is.
	CauseMissingCallEdge = "a call written with this name did not resolve to it"
	// CauseBelowUnreached: something does call it, and that caller is unreached too.
	// The cause is the caller's, one level up.
	CauseBelowUnreached = "every caller is itself unreached"
	// CauseNeverCalled: no call anywhere in the program is written with this name. A
	// framework invokes it -- a decorator's wrapper, a form hook, a template tag, a
	// signal handler, an inherited method dispatched on a receiver -- or it is dead.
	// Either way it is not evidence of a route that was missed.
	CauseNeverCalled = "nothing in the program calls them by name"
)

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

// ClassCount is how many entry points of one kind the application exposes, and who can
// reach them.
type ClassCount struct {
	Kind  string
	Trust ir.Trust
	Count int
}

// Classes counts the enumerated entry points by kind, largest first.
//
// The surface is the primary output (ADR-009) and it stopped being one number the moment
// it stopped being all routes. A total that folds seventeen cron jobs into a route count
// says the application answers seventeen more requests than it does, and a reader
// checking the enumeration against the application they know would be right to distrust
// the whole report over it. So the classes are counted apart and the total is their sum.
func (s Surface) Classes() []ClassCount {
	byKind := map[string]*ClassCount{}
	var order []string
	for _, e := range s.Entries {
		c, ok := byKind[e.EntryPoint.Kind]
		if !ok {
			c = &ClassCount{Kind: e.EntryPoint.Kind, Trust: e.TrustLevel()}
			byKind[e.EntryPoint.Kind] = c
			order = append(order, e.EntryPoint.Kind)
		}
		c.Count++
	}
	sort.Strings(order)
	out := make([]ClassCount, 0, len(order))
	for _, k := range order {
		out = append(out, *byKind[k])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// RemoteEntries counts the entry points a caller outside the process can reach.
//
// This, and not the total, is what the completeness question is about: a program with
// sixteen process starts and no route has no remote surface at all, and reading the
// total would say it had sixteen.
func (s Surface) RemoteEntries() int {
	n := 0
	for _, e := range s.Entries {
		if e.TrustLevel() == ir.Remote {
			n++
		}
	}
	return n
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
	var nonApplication []EntryFacts

	for _, ep := range d.EntryPoints {
		fn := ix.FuncByID[ep.FunctionID]
		loc := ep.Loc
		if fn != nil {
			loc = fn.Loc
		} else if loc.File == "" {
			loc.File = ep.Detail["module"]
		}
		facts := EntryFacts{
			EntryPoint: ep,
			Function:   fn,
			Provenance: ix.ProvenanceOf(loc),
			Method:     ep.Detail["method"],
			Path:       ep.Detail["path"],
			Group:      groupOf(ep, fn),
		}
		facts.Controls = controlsOf(ep, fn, m, p)
		if !ix.InApplicationSurface(loc) {
			if facts.Provenance != "" {
				nonApplication = append(nonApplication, facts)
			}
			continue
		}
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
	sort.Slice(nonApplication, func(i, j int) bool {
		if nonApplication[i].Provenance != nonApplication[j].Provenance {
			return nonApplication[i].Provenance < nonApplication[j].Provenance
		}
		return nonApplication[i].Label() < nonApplication[j].Label()
	})

	return Surface{
		Entries:               entries,
		NonApplicationEntries: nonApplication,
		Completeness:          completenessOf(ix, m, entries),
	}
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
func completenessOf(ix *ir.Index, m model.Model, entries []EntryFacts) Completeness {
	// Which value kinds and which framework globals mean "caller-supplied", according to
	// the model rather than to anything hardcoded here.
	kinds := map[string]bool{}
	globals := map[string]bool{}
	// Paths a request object exposes: "body", "query", "params" and the like, kept
	// under the PARAMETER POSITION the rule names them at. Used here as evidence of
	// HANDLER SHAPE, never to seed taint. A function that reads .body off its own
	// first parameter looks exactly like a request handler whether or not any route
	// pointing at it was recognized, and that is the whole question being asked.
	//
	// Without this the check is blind precisely where it is needed most: frameworks that
	// pass a request object into the handler anchor their rule to an enumerated entry
	// point, so a handler nobody enumerated leaves no trace at all.
	//
	// The position is part of the rule and dropping it is what made the count
	// unusable. Flattened into one set matched against ANY parameter, the union of
	// every framework's request shape matches an enormous amount of code that is not
	// a handler at all: searxng's engine plugins take an outbound `params` dict as
	// their SECOND argument and set params["headers"], and 62 of them counted as
	// unreached request handlers. Position is the cheapest thing that tells a request
	// object apart from a domain object carrying a colliding field name, and it is
	// already written down.
	pathsAt := map[int]map[string]bool{}
	for _, c := range m.Classifications {
		if c.Class != m.UntrustedClass() {
			continue
		}
		for _, r := range c.Rules {
			// A source only a person with a shell can supply is not evidence that a
			// route was missed, which is the only thing this count asks about.
			if r.Trust != "" && r.Trust != ir.Remote {
				continue
			}
			switch r.Match {
			case model.MatchValueKind:
				kinds[r.ValueKind] = true
			case model.MatchGlobalProperty:
				globals[r.Symbol] = true
			case model.MatchEntryParamProperty:
				if pathsAt[r.ParamIndex] == nil {
					pathsAt[r.ParamIndex] = map[string]bool{}
				}
				for _, p := range r.Paths {
					pathsAt[r.ParamIndex][p] = true
				}
			}
		}
	}

	// REMOTE entry points only.
	//
	// The question this counts is whether the enumerated surface accounts for the code
	// that reads what a CALLER SENT, and a cron job reaching a handler does not mean a
	// request can. Letting background entries into the roots would answer a different
	// question with the same number and quietly lower the bar -- the exact failure
	// Suspect's own comment records, where a surface got bigger and the gate switched
	// off without getting any more complete.
	roots := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.EntryPoint.FunctionID != "" && entry.EntryPoint.TrustLevel() == ir.Remote {
			roots = append(roots, entry.EntryPoint.FunctionID)
		}
	}
	reachable := ix.ReachableFrom(roots)

	var out Completeness
	var unreached []*ir.Function
	evidence := map[string]string{}
	for _, fn := range ix.IR.Functions {
		reads, why := readsCallerInput(ix, fn, kinds, globals, pathsAt)
		if !reads {
			continue
		}
		// A function that cannot serve a request cannot be evidence that a route
		// serving one was missed.
		if !ix.InApplicationSurface(fn.Loc) {
			out.NonProductionInputFunctions++
			continue
		}
		out.InputFunctions++
		if !reachable[fn.ID] {
			out.UnreachedInputFunctions++
			unreached = append(unreached, fn)
			evidence[fn.ID] = why
		}
	}
	out.Unreached = explainUnreached(ix, reachable, unreached, evidence)
	return out
}

// readsCallerInput reports whether a function handles caller-supplied input, and what
// made it look that way.
func readsCallerInput(ix *ir.Index, fn *ir.Function, kinds, globals map[string]bool, pathsAt map[int]map[string]bool) (bool, string) {
	index := make(map[string]int, len(fn.Params))
	for i, p := range fn.Params {
		index[p.ValueID] = i
	}
	for _, v := range fn.Values {
		if kinds[string(v.Kind)] {
			return true, string(v.Kind)
		}
		base := ix.ValueByID[v.Base]
		if base != nil && base.Kind == "global" && globals[base.Name] {
			return true, base.Name + "." + v.Path
		}
		if v.Kind != ir.ValueProperty {
			continue
		}
		i, ok := index[v.Base]
		if !ok {
			continue
		}
		if pathsAt[i][firstSegment(v.Path)] {
			name := fn.Params[i].Name
			if name == "" {
				name = "arg" + strconv.Itoa(i)
			}
			return true, name + "." + firstSegment(v.Path)
		}
	}
	return false, ""
}

// sampleSize bounds each cause's listing. Three is enough to see what KIND of code a
// cause covers, which is the question; the counts carry the scale.
const sampleSize = 3

// moduleSize bounds the directory rollup per cause.
const moduleSize = 3

// explainUnreached says why each unreached function cannot be reached, grouped by
// cause and bounded.
//
// Only the call graph is consulted, because only the call graph can be observed. The
// engine cannot know that Django calls a form's clean_ hooks or that Tornado
// dispatches an inherited method on a handler; it can know that no call site in the
// program is written with that name, which is a different claim and a checkable one.
func explainUnreached(ix *ir.Index, reachable map[string]bool, unreached []*ir.Function, evidence map[string]string) []UnreachedGroup {
	if len(unreached) == 0 {
		return nil
	}
	// Names written at call sites that did not resolve to a local function, and
	// whether the code writing them is reached. Both spellings are collected: a
	// method call records the property name, a plain call records the written name.
	named := map[string]bool{}
	namedFromReached := map[string]bool{}
	for _, fn := range ix.IR.Functions {
		for _, c := range fn.Calls {
			if c.Callee.Kind == "local" && c.Callee.FunctionID != "" {
				continue
			}
			for _, n := range []string{c.Method, c.Callee.Name} {
				if n == "" {
					continue
				}
				named[n] = true
				if reachable[fn.ID] {
					namedFromReached[n] = true
				}
			}
		}
	}

	order := []string{CauseMissingCallEdge, CauseBelowUnreached, CauseNeverCalled}
	groups := map[string]*UnreachedGroup{}
	dirs := map[string]map[string]int{}
	for _, fn := range unreached {
		cause, detail := CauseNeverCalled, evidence[fn.ID]
		switch {
		case len(ix.CallSitesOf[fn.ID]) > 0:
			cause = CauseBelowUnreached
			if caller := ix.OwnerOfCall[ix.CallSitesOf[fn.ID][0].ID]; caller != nil {
				detail = "called by " + caller.Name + ", which is unreached too"
			}
		case named[fn.Name]:
			cause = CauseMissingCallEdge
		}
		g := groups[cause]
		if g == nil {
			g = &UnreachedGroup{Cause: cause}
			groups[cause] = g
			dirs[cause] = map[string]int{}
		}
		g.Count++
		if cause == CauseMissingCallEdge && namedFromReached[fn.Name] {
			g.FromReachedCode++
		}
		dirs[cause][dirOf(fn.Loc.File)]++
		if len(g.Sample) < sampleSize {
			g.Sample = append(g.Sample, UnreachedFunction{Name: fn.Name, Loc: fn.Loc, Detail: detail})
		}
	}

	var out []UnreachedGroup
	for _, cause := range order {
		g := groups[cause]
		if g == nil {
			continue
		}
		g.Modules = topModules(dirs[cause])
		out = append(out, *g)
	}
	return out
}

// topModules ranks directories by how many unreached functions they hold. This is the
// line that made searxng's number readable at a glance: 100 of 134 in searx/engines,
// which are plugins the router loads by name and not routes anybody failed to find.
func topModules(counts map[string]int) []ModuleCount {
	out := make([]ModuleCount, 0, len(counts))
	for dir, n := range counts {
		out = append(out, ModuleCount{Dir: dir, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Dir < out[j].Dir
	})
	if len(out) > moduleSize {
		out = out[:moduleSize]
	}
	return out
}

// dirOf is the directory a file sits in, which is the granularity a reader groups code
// at. A file with no directory answers for itself.
func dirOf(file string) string {
	if i := strings.LastIndexByte(file, '/'); i > 0 {
		return file[:i]
	}
	return file
}

// firstSegment is the leading name of a dotted access path: "body.target" -> "body".
func firstSegment(path string) string {
	if i := strings.IndexByte(path, '.'); i >= 0 {
		return path[:i]
	}
	return path
}
