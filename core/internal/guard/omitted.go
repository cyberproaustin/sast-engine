// A control the program HAS, applied on one way in and not on the way in beside it.
//
// Everything else in this package reads a refusal that was written and then walked past.
// This reads a refusal that was written on one path and never written on another, where
// both paths end at the same operation on the same record. Nothing is missing from the
// program's vocabulary -- the check exists, it is spelled correctly, and it runs. What is
// missing is its COVERAGE, and coverage is a fact about the graph rather than about any
// line in it, which is why no rule that reads one site at a time can state it.
//
//	if snapshot_id:
//	    snapshot = _find_snapshot_by_ref(snapshot_id)
//	    if snapshot and not can_view_snapshot(request, snapshot):   # asked here
//	        return _private_snapshot_auth_redirect(request, snapshot, path)
//	else:
//	    snapshot = qs.order_by("-bookmarked_at").first()            # and not here
//	...
//	return redirect(f"/{snapshot.url_path}/{path}")                 # both arrive here
//
// # Why this is not "an entry point without a control"
//
// The convention analysis (ADR-010) already reports a route missing what its peers apply,
// and it cannot tell an endpoint that is public BY DESIGN from one that forgot -- medplum
// mounts a public FHIR router beside a protected one on purpose, and the CWE-306 rule
// reported it until the design said not to. The difference here is not a better name list.
// It is that the two paths CONVERGE: they produce the same value and hand it to the same
// operation, so the author cannot have meant one of them to be public without meaning the
// other to be. A public route beside a protected one shares no value and no sink, and
// nothing below will pair them.
//
// # Two enumerations of one weakness
//
// "The path beside it" is spelled two ways in real programs, and they are the same
// judgement over different populations:
//
//   - BRANCH -- two arms of one function that both define the record and both reach the
//     operation, where the check dominates only one of them. Evidence: the dominator
//     relation, which is exactly "there is a way here that did not pass the check".
//   - PEER -- sibling methods of one class that perform the SAME call on values out of the
//     SAME parameter, where two of them gate it on a check and one does not. Evidence: the
//     population, narrowed until the members are doing literally the same thing.
//
// Both are reported under one rule id because the weakness, the citation and the fix are
// identical; only the enumeration of "beside" differs.
//
// # Why this is not an eighth kind
//
// ADR-016's test is whether an existing kind would have to be given a fact it does not
// have. This one needs no new fact: the question is "can the operation still happen
// without the check", which is the question this package was created to ask, asked of a
// dominator rather than of a fall-through. It reads blocks, successors and dominance --
// all of it already in the IR and already read here. Being a second SHAPE in the graph
// kind is what this is, and a shape is not a kind. The one thing genuinely new is the
// comparison target, and the sibling differential in this same package established that a
// graph rule may judge one function against another; the peer enumeration below only
// changes what makes two functions comparable.
package guard

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// decides reports whether a name says the call DECIDES access rather than fetching,
// shaping or recording something.
//
// Same construction as isCheck and for the same measured reason: `getPermissions` fetches
// where `hasPermission` judges, and a rule reading only the word would call the lookup a
// control and then report every path that did not perform one. The stem list is
// deliberately narrower than the sibling differential's: that rule fires on a pair whose
// direction is known, and can afford `validate` and `verify`; this one fires on a
// convergence and would otherwise report every input-validation asymmetry in a program.
func decides(name string, shape *model.OmittedControlGuard) bool {
	// The last segment, never the whole expression. `client.createAuthorizationURLWithPKCE`
	// begins with `client`, so a prefix test on the spelled-out call answers a question
	// about the receiver -- and documenso's CSC OAuth builder was reported three times as
	// an access decision for exactly that reason before this line read the leaf.
	leaf := lastSegment(name)
	n := letters(leaf)
	if n == "" || hasPrefix(leaf, shape.Retrieves) {
		return false
	}
	for _, stem := range shape.Decides {
		if strings.Contains(n, stem) {
			return true
		}
	}
	return false
}

// operates reports whether a call DOES something with the record, as opposed to writing
// it down, reshaping it, or handing back a helper.
//
// `json.dumps(event)` and `str(snapshot.id)` carry a value without acting on it, and a
// finding that pointed at one of them would name the wrong line: the operation is what the
// reshaped value was then handed to. A RETRIEVAL is excluded for a sharper reason, and it
// was measured: `self.get_serializer(request.data)` appears in twelve unrelated view
// classes of one paperless-ngx module, and taking it for an operation made every one of
// them a peer of every other. Fetching a thing is not doing anything to the record.
func operates(name string, shape *model.OmittedControlGuard) bool {
	if name == "" || decides(name, shape) || hasPrefix(lastSegment(name), shape.Retrieves) {
		return false
	}
	leaf := letters(lastSegment(name))
	for _, w := range shape.Records {
		if strings.HasPrefix(leaf, w) {
			return false
		}
	}
	for _, w := range shape.Inert {
		if leaf == w {
			return false
		}
	}
	return true
}

// signature is the parameter list, by name and position.
//
// The IR names no class, so "sibling method" has to be said some other way, and the
// argument list is the strongest thing two functions in one module can share without one.
// Handlers of one dispatcher have identical signatures because the dispatcher calls them
// identically; two view methods that merely both take `request` do not, and that
// difference is what stops a four-thousand-line module becoming one peer group.
func signature(fn *ir.Function) string {
	names := make([]string, 0, len(fn.Params))
	for _, p := range fn.Params {
		names = append(names, p.Name)
	}
	return strings.Join(names, ",")
}

// nameOf is the call's name as this rule compares names: the final segment, because
// `self.send` and `send` are one call and the receiver's spelling is not evidence.
func nameOf(c *ir.Call) string {
	if c.Callee.Symbol != "" {
		return c.Callee.Symbol
	}
	if c.Callee.Name != "" {
		return c.Callee.Name
	}
	return c.Method
}

// variables is what a function's locals are called, and where each one was assigned.
//
// The two frontends disagree about how to lower a variable assigned twice -- TypeScript
// makes one value with two edges into it, Python makes two values with one edge each --
// so the identity that survives both is the NAME, and the definition sites are the blocks
// of the assignment edges. Synthetic names are dropped: a frontend calls the result of an
// `or` "either" and an f-string "f-string" in every function it lowers, and treating those
// as one variable would join code that shares nothing.
type variables struct {
	defs   map[string]map[string]bool // variable name -> blocks that assign it
	values map[string]map[string]bool // variable name -> value ids carrying it
	root   map[string]string          // value id -> the variable it is a part of
}

var syntheticNames = map[string]bool{
	"comparison": true, "either": true, "conditional": true, "concat": true,
	"local": true, "f-string": true, "template": true, "unresolved": true,
	"spread": true, "await": true,
}

func syntheticName(name string) bool {
	if name == "" || syntheticNames[name] {
		return true
	}
	// `[sequence]`, `[array]`, `[comprehension]`, `{object}`: a shape, not a variable.
	return strings.ContainsAny(name, "[{")
}

func variablesOf(fn *ir.Function) *variables {
	v := &variables{
		defs:   map[string]map[string]bool{},
		values: map[string]map[string]bool{},
		root:   map[string]string{},
	}
	byID := make(map[string]*ir.Value, len(fn.Values))
	for _, val := range fn.Values {
		byID[val.ID] = val
		if val.Kind != ir.ValueLocal || syntheticName(val.Name) {
			continue
		}
		if v.values[val.Name] == nil {
			v.values[val.Name] = map[string]bool{}
		}
		v.values[val.Name][val.ID] = true
		v.root[val.ID] = val.Name
	}
	// A property reads a part of the record the check was about: `snapshot.url_path` is
	// still the snapshot, and a check on the whole covers the part.
	for id, val := range byID {
		if val.Kind != ir.ValueProperty {
			continue
		}
		base := val.Base
		for hops := 0; hops < 6 && base != ""; hops++ {
			if name, ok := v.root[base]; ok {
				v.root[id] = name
				break
			}
			up := byID[base]
			if up == nil || up.Kind != ir.ValueProperty {
				break
			}
			base = up.Base
		}
	}
	for _, f := range fn.Flows {
		if f.Kind != "assign" || f.Block == "" {
			continue
		}
		name, ok := v.root[f.To]
		if !ok || !v.values[name][f.To] {
			continue
		}
		if v.defs[name] == nil {
			v.defs[name] = map[string]bool{}
		}
		v.defs[name][f.Block] = true
	}
	return v
}

// carries is every value the named variable flowed into, so an operation on the record
// can be recognised however many hands it passed through first.
func (v *variables) carries(fn *ir.Function, name string) map[string]bool {
	out := map[string]bool{}
	for id := range v.values[name] {
		out[id] = true
	}
	for id, root := range v.root {
		if root == name {
			out[id] = true
		}
	}
	for round := 0; round < 8; round++ {
		changed := false
		for _, f := range fn.Flows {
			if out[f.From] && !out[f.To] {
				out[f.To], changed = true, true
			}
		}
		if !changed {
			break
		}
	}
	return out
}

// omittedOnBranch reports an operation reachable by a path the program's own access check
// does not stand on, where the path beside it defines the same record and passes it.
func omittedOnBranch(ix *ir.Index, fn *ir.Function, g *cfg.Graph, rule model.GuardRule) []taint.Finding {
	shape := rule.Omits
	if ix.InTestModule(fn.Loc) || len(fn.Blocks) == 0 {
		return nil
	}
	vars := variablesOf(fn)
	if len(vars.defs) == 0 {
		return nil
	}

	// Every block a decision stands in, so a second decision covering the operation can
	// clear it. A handler that asks twice has asked.
	covering := map[string]bool{}
	for _, c := range fn.Calls {
		if c.Block != "" && decides(nameOf(c), shape) {
			covering[c.Block] = true
		}
	}

	var out []taint.Finding
	reported := map[string]bool{}
	for _, check := range fn.Calls {
		if check.Block == "" || !g.Reachable(check.Block) || !decides(nameOf(check), shape) {
			continue
		}
		// A decision that decides nothing is decoration. IsGuard is this package's own
		// test for enforcement: some way out of the branch leaves the function rather
		// than rejoining the main line.
		if !g.IsGuard(check.Block) {
			continue
		}
		for _, a := range check.Args {
			subject, ok := vars.root[a.ValueID]
			if !ok || reported[subject] {
				continue
			}
			f, ok := branchFinding(ix, fn, g, vars, covering, check, subject, rule)
			if !ok {
				continue
			}
			reported[subject] = true
			out = append(out, f)
		}
	}
	return out
}

func branchFinding(ix *ir.Index, fn *ir.Function, g *cfg.Graph, vars *variables,
	covering map[string]bool, check *ir.Call, subject string, rule model.GuardRule) (taint.Finding, bool) {
	// A definition on a path the check does not stand on. Neither block may dominate the
	// other: an assignment BEFORE the branch is the same path, not the one beside it,
	// which is what keeps `snapshot = None` at the top of a handler from counting.
	var siblings []string
	for bd := range vars.defs[subject] {
		if bd == check.Block || !g.Reachable(bd) {
			continue
		}
		if g.Dominates(check.Block, bd) || g.Dominates(bd, check.Block) {
			continue
		}
		siblings = append(siblings, bd)
	}
	if len(siblings) == 0 {
		return taint.Finding{}, false
	}
	sort.Strings(siblings)

	carried := vars.carries(fn, subject)
	var op *ir.Call
	var from string
	for _, c := range fn.Calls {
		if c.ID == check.ID || c.Block == "" || c.Block == check.Block || !g.Reachable(c.Block) {
			continue
		}
		if !operates(nameOf(c), rule.Omits) || !usesAny(c, carried) {
			continue
		}
		// The check does not stand on the way here, and yet the checked path arrives
		// here too: this is the same operation, reached two ways.
		if g.Dominates(check.Block, c.Block) || !g.Reaches(check.Block, c.Block) {
			continue
		}
		if coveredBy(g, covering, check.Block, c.Block) {
			continue
		}
		reached := ""
		for _, bd := range siblings {
			if bd == c.Block || g.Reaches(bd, c.Block) {
				reached = bd
				break
			}
		}
		if reached == "" {
			continue
		}
		if op == nil || earlier(c, op) {
			op, from = c, reached
		}
	}
	if op == nil {
		return taint.Finding{}, false
	}
	if _, ok := taint.EntryOf(ix, fn); !ok {
		return taint.Finding{}, false
	}
	return branchOmissionFinding(ix, fn, check, op, subject, defLoc(fn, vars, subject, from), rule), true
}

// defLoc is where the unchecked path assigned the record, so the finding can point at the
// line rather than at a block identifier nobody can read.
func defLoc(fn *ir.Function, vars *variables, subject, block string) ir.Loc {
	for _, f := range fn.Flows {
		if f.Kind == "assign" && f.Block == block && vars.root[f.To] == subject {
			return f.Loc
		}
	}
	return fn.Loc
}

// coveredBy reports whether some OTHER decision stands unavoidably before the operation.
// A handler that asks a second question the first branch skipped has still asked one.
func coveredBy(g *cfg.Graph, covering map[string]bool, checkBlock, opBlock string) bool {
	for b := range covering {
		if b != checkBlock && g.Dominates(b, opBlock) {
			return true
		}
	}
	return false
}

func earlier(a, b *ir.Call) bool {
	if a.Loc.Line != b.Loc.Line {
		return a.Loc.Line < b.Loc.Line
	}
	return a.Loc.Column < b.Loc.Column
}

func usesAny(c *ir.Call, values map[string]bool) bool {
	for _, a := range c.Args {
		if values[a.ValueID] {
			return true
		}
	}
	return values[c.ReceiverID]
}

// --- the peer enumeration -------------------------------------------------
//
// Sibling handlers of one class, doing the same thing to the same input, where the
// majority gate it on a control and one does not.

// site is one operation performed by one function, with the controls that stand over it.
type site struct {
	fn    *ir.Function
	call  *ir.Call
	gates map[string]bool
	// input is the parameter the operated-on value came out of, kept for the finding.
	input string
}

// peerIndex groups operations that are literally the same operation on the same input.
type peerIndex struct {
	rule    model.GuardRule
	byGroup map[string][]site
	order   []string
}

func newPeerIndex(rule model.GuardRule) *peerIndex {
	return &peerIndex{rule: rule, byGroup: map[string][]site{}}
}

// observe records what one function does with its parameters.
func (p *peerIndex) observe(ix *ir.Index, fn *ir.Function, g *cfg.Graph) {
	shape := p.rule.Omits
	if ix.InTestModule(fn.Loc) || len(fn.Params) == 0 || fn.Module == "" {
		return
	}
	// Which parameter each value came out of. A group is only a group if its members
	// operate on the same input, and a parameter name is the only spelling of "the same
	// input" that two functions can share.
	type origin struct {
		param string
		hops  int
	}
	from := map[string]origin{}
	for _, prm := range fn.Params {
		if prm.Name == "" || prm.Name == "self" || prm.Name == "this" || prm.ValueID == "" {
			continue
		}
		from[prm.ValueID] = origin{param: prm.Name}
	}
	if len(from) == 0 {
		return
	}
	// Three ways a parameter reaches a call: an edge, a property of it, and the RESULT of
	// a call it was handed. The third is not optional -- neither frontend draws a flow
	// edge from a call's argument to its result, so without it
	// `self.send(json.dumps(event))` is a send of nothing anybody passed in.
	//
	// It is also what makes the distance matter. Follow results far enough and every value
	// in a handler descends from `request`, and two handlers that share nothing become
	// peers. Measured on paperless-ngx: unlimited, this paired `Response(meta)` with
	// `Response(resp_data)` six hops down two different document lookups, and paired a
	// `Document.objects.filter(pk__in=serializer.validated_data["document_ids"])` with an
	// unrelated audit query -- three findings, all false, all of them a value that had
	// stopped being the parameter several calls ago. Two hops is `json.dumps(event)` and
	// `event["data"]`, which is as far as a value stays recognisably the thing the
	// parameter named.
	const reach = 2
	for round := 0; round < reach; round++ {
		changed := false
		note := func(id, param string, hops int) {
			if id == "" || hops > reach {
				return
			}
			if got, seen := from[id]; seen && got.hops <= hops {
				return
			}
			from[id], changed = origin{param: param, hops: hops}, true
		}
		for _, f := range fn.Flows {
			if src, ok := from[f.From]; ok {
				// An assignment renames a value; it does not take it further away.
				step := 1
				if f.Kind == "assign" {
					step = 0
				}
				note(f.To, src.param, src.hops+step)
			}
		}
		for _, v := range fn.Values {
			if v.Kind != ir.ValueProperty || v.Base == "" {
				continue
			}
			if src, ok := from[v.Base]; ok {
				note(v.ID, src.param, src.hops+1)
			}
		}
		for _, c := range fn.Calls {
			if c.ResultID == "" {
				continue
			}
			for _, a := range c.Args {
				if src, ok := from[a.ValueID]; ok {
					note(c.ResultID, src.param, src.hops+1)
					break
				}
			}
		}
		if !changed {
			break
		}
	}

	inputs := func(c *ir.Call) map[string]bool {
		out := map[string]bool{}
		for _, a := range c.Args {
			if src, ok := from[a.ValueID]; ok {
				out[src.param] = true
			}
		}
		return out
	}

	// Every decision this function makes, with the inputs it was asked about.
	type control struct {
		name   string
		block  string
		inputs map[string]bool
	}
	var controls []control
	for _, c := range fn.Calls {
		if c.Block == "" || !g.Reachable(c.Block) || !decides(nameOf(c), shape) {
			continue
		}
		in := inputs(c)
		if len(in) == 0 {
			continue
		}
		controls = append(controls, control{name: letters(lastSegment(nameOf(c))), block: c.Block, inputs: in})
	}

	seen := map[string]bool{}
	for _, c := range fn.Calls {
		if c.Block == "" || !g.Reachable(c.Block) || !operates(nameOf(c), shape) {
			continue
		}
		in := inputs(c)
		if len(in) != 1 {
			// More than one parameter, or none: either way two functions cannot be said
			// to be doing the same thing to the same value.
			continue
		}
		var input string
		for k := range in {
			input = k
		}
		key := fn.Module + "|" + signature(fn) + "|" + nameOf(c) + "|" + input
		gates := map[string]bool{}
		for _, ctl := range controls {
			if !ctl.inputs[input] {
				continue
			}
			// Standing before the operation on every path, or deciding whether it runs
			// at all. The second is what an `elif` looks like, and it is the shape the
			// measured case is written in.
			if g.Dominates(ctl.block, c.Block) || g.ControlDependsOn(c.Block, ctl.block) {
				gates[ctl.name] = true
			}
		}
		if _, dup := seen[key]; dup {
			// The outermost call in a nest is the operation; the inner ones handed it a
			// reshaped value. Frontends emit inner calls first, so the last one wins.
			for i := len(p.byGroup[key]) - 1; i >= 0; i-- {
				if p.byGroup[key][i].fn.ID == fn.ID {
					p.byGroup[key][i] = site{fn: fn, call: c, gates: gates, input: input}
					break
				}
			}
			continue
		}
		seen[key] = true
		if _, ok := p.byGroup[key]; !ok {
			p.order = append(p.order, key)
		}
		p.byGroup[key] = append(p.byGroup[key], site{fn: fn, call: c, gates: gates, input: input})
	}
}

// report names the member of a group that skips what the rest of the group applies.
//
// Two peers rather than one is the whole safety margin. One handler differing from one
// other handler is the ordinary asymmetry of every application; two handlers agreeing on
// a control and a third omitting it is a convention with a hole in it, and the engine can
// cite the convention rather than guessing at one (ADR-010).
func (p *peerIndex) report(ix *ir.Index) []taint.Finding {
	var out []taint.Finding
	for _, key := range p.order {
		group := p.byGroup[key]
		if len(group) < 3 {
			continue
		}
		applied := map[string]int{}
		for _, s := range group {
			for name := range s.gates {
				applied[name]++
			}
		}
		var names []string
		for name := range applied {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if applied[name] < 2 || applied[name] == len(group) {
				continue
			}
			var peer *site
			for i := range group {
				if group[i].gates[name] {
					peer = &group[i]
					break
				}
			}
			for i := range group {
				if group[i].gates[name] || peer == nil {
					continue
				}
				out = append(out, peerOmissionFinding(ix, &group[i], peer, name, p.rule))
			}
		}
	}
	return out
}

// --- findings -------------------------------------------------------------

func branchOmissionFinding(ix *ir.Index, fn *ir.Function, check, op *ir.Call,
	subject string, defined ir.Loc, rule model.GuardRule) taint.Finding {
	asks := callName(ix, check)
	acts := callName(ix, op)
	return taint.Finding{
		Analysis:     rule.ID,
		DataClass:    "control-flow",
		ChannelID:    rule.ID,
		Class:        rule.Finding,
		CWE:          rule.CWE,
		Message:      rule.Reason,
		SinkLoc:      op.Loc,
		SinkSymbol:   acts,
		SinkFunction: fn.Name,
		SinkRational: rule.Rationale,
		SourceLabel:  subject,
		SourceLoc:    check.Loc,
		InTestModule: ix.InTestModule(op.Loc),
		Path: []taint.Hop{
			{Loc: check.Loc, Description: fmt.Sprintf("%s() decides whether the caller may have this `%s`, on one branch", asks, subject), Resolution: ir.Resolved},
			{Loc: defined, Description: fmt.Sprintf("the branch beside it assigns `%s` and asks nothing", subject), Resolution: ir.Resolved},
			{Loc: op.Loc, Description: fmt.Sprintf("%s() acts on the same `%s` here, reachable either way", acts, subject), Resolution: ir.Resolved},
		},
		SinkArgIndex:  -1,
		Confidence:    taint.High,
		EntryAnchored: true,
		EntryPoint:    entryAbove(ix, parents(ix), fn),
	}
}

func peerOmissionFinding(ix *ir.Index, weak, peer *site, control string, rule model.GuardRule) taint.Finding {
	acts := callName(ix, weak.call)
	return taint.Finding{
		Analysis:     rule.ID,
		DataClass:    "control-flow",
		ChannelID:    rule.ID,
		Class:        rule.Finding,
		CWE:          rule.CWE,
		Message:      rule.Reason,
		SinkLoc:      weak.call.Loc,
		SinkSymbol:   acts,
		SinkFunction: weak.fn.Name,
		SinkRational: rule.Rationale,
		SourceLabel:  weak.input,
		SourceLoc:    peer.call.Loc,
		InTestModule: ix.InTestModule(weak.call.Loc),
		Path: []taint.Hop{
			{Loc: peer.fn.Loc, Description: fmt.Sprintf("%s() performs the same %s() on the same `%s`", peer.fn.Name, acts, weak.input), Resolution: ir.Resolved},
			{Loc: peer.call.Loc, Description: fmt.Sprintf("and reaches it only when %s says so", control), Resolution: ir.Resolved},
			{Loc: weak.call.Loc, Description: fmt.Sprintf("%s() reaches it here with no such question asked", weak.fn.Name), Resolution: ir.Resolved},
		},
		SinkArgIndex:  -1,
		Confidence:    taint.High,
		EntryAnchored: true,
		EntryPoint:    entryAbove(ix, parents(ix), weak.fn),
	}
}
