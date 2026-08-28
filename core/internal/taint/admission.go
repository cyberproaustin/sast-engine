package taint

import (
	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

// A value the program ADMITTED is not a value the caller chose.
//
// `if (isValidReturnToUrl(body.returnTo, domainConfig)) { signInPage = body.returnTo }`
// carries the caller's bytes into the redirect, and the flow analysis is right that it
// does. What it misses is that those bytes got there only by matching a URL the
// deployment registered: the caller SELECTED a destination out of a set the program
// already knew, and choosing from a set somebody else wrote down is not choosing.
//
// This is the same shape as anchoredRegexGuardClears one file over, and the difference is
// what the proof rests on. There, the accepted LANGUAGE is examined and shown not to spell
// the syntax the sink interprets. Here there is no language to examine -- the validator is
// ordinary application code -- so the proof is that the program compared the value against
// DATA OF ITS OWN and let it through on the strength of that comparison. Four independent
// facts have to meet, and none of them is the validator's name:
//
//   - the callee settles its answer on an EQUALITY between the value, or the part of it
//     this sink turns on, and a value the program holds (constrains, programsOwnData);
//   - the sink's CONTEXT is one where equality on that part answers the question the
//     weakness asks -- only a redirect, today (admissionParts);
//   - the caller's value reaches the sink only where that answer was YES: the sink itself
//     sits on the branch (sinkSelected), or the assignment that carries it does
//     (definitionSelected), or the function's every way out does (returnedConstrained);
//   - and nothing else defines the value from anywhere the decision did not allow.
//
// Measured on medplum, whose four CWE-601 findings are all this shape, all false, and all
// silent now: 41 reported findings became 37 across that repository and 28 adjudicated-true
// findings across ten repositories were untouched. The SQL injection beside them is NOT
// this shape and is still reported -- `isValidTableName` is registered as an express-
// validator chain rather than called in the handler, so no branch in the handler is about
// the value at all, and an anchored `\w+` is the other file's proof rather than this one's.
//
// What must NOT clear is a function that merely looks at the value -- logs it, measures
// its length, counts it -- and the reason it does not is that looking is not comparing:
// there is no equality against the program's own data anywhere in it. Nor a check whose
// answer is discarded, nor one whose polarity runs the other way, nor an equality on a
// part of the value that does not decide the question. testdata/registered-destination
// holds all of those as positives beside the negatives, on identical dataflow.

// admissionParts names the parts of a value which, proved equal to data the program
// itself owns, answer the question THIS sink context asks.
//
// Per context, because equality on a part settles one question and not another. A
// destination whose host equals a host the program registered is a destination the
// program chose, and that is the whole of CWE-601: the weakness is that the application
// lends its name to a site somebody else picked. The same proof says nothing about what
// a database will execute or what a filesystem will open, so no other context is listed
// -- and a context that is not listed gets no admission at all, which is the safe
// direction (ADR-003).
//
// "" is the whole value: `uri === requestedUri` pins every byte and needs no part.
func admissionParts(context string) []string {
	switch context {
	case "redirect":
		return []string{"", "origin", "host", "hostname"}
	default:
		return nil
	}
}

// admission holds the caches one judgement needs. Kept off the engine because it is
// built only where a channel's context declares parts, which is at most once per
// finding.
type admission struct {
	e     *engine
	parts []string

	graphs  map[string]*cfg.Graph
	decides map[string]bool
	exprs   map[string]expression
}

// expression names a value by the root it was read from and the path read off it.
type expression struct {
	root  string
	path  string
	known bool
}

// admittedAgainstProgramValues reports whether the caller's value reached this sink only
// because the program matched it against data of its own.
func (e *engine) admittedAgainstProgramValues(sink *ir.Call, valueID, context string) bool {
	parts := admissionParts(context)
	if len(parts) == 0 || sink.Block == "" {
		return false
	}
	// A match against registered data changes what the caller can CHOOSE. It does not
	// make a password non-secret or a token unpredictable, so only the classes that are
	// about caller-supplied text can be cleared this way. Stored caller input is the
	// same text after a round trip through a database, and a decision taken on the value
	// just read is a decision on that text.
	if e.class.Class != "untrusted-input" && e.class.Class != "second-order-input" {
		return false
	}
	a := &admission{
		e:       e,
		parts:   parts,
		graphs:  map[string]*cfg.Graph{},
		decides: map[string]bool{},
		exprs:   map[string]expression{},
	}
	return a.walkWitness(sink, valueID)
}

// walkWitness follows the path the finding would print, backwards, asking at each step
// whether that step was one the program allowed only after deciding about the value.
func (a *admission) walkWitness(sink *ir.Call, valueID string) bool {
	seen := map[string]bool{}
	for id := valueID; id != "" && !seen[id]; {
		seen[id] = true
		if a.sinkSelected(sink, id) || a.returnedConstrained(id) {
			return true
		}
		ed, ok := a.e.pred[id]
		if !ok {
			return false
		}
		if a.definitionSelected(ed.from, id) {
			return true
		}
		id = ed.from
	}
	return false
}

// sinkSelected is the shape where the value is decided once and used afterwards:
//
//	if (!isAllowed(to)) return res.status(400).send("no");
//	res.redirect(to);
//
// The operation itself sits on the branch the answer YES selected, so reaching it at all
// is the proof.
func (a *admission) sinkSelected(sink *ir.Call, valueID string) bool {
	fn := a.e.ix.OwnerOfCall[sink.ID]
	if fn == nil {
		return false
	}
	g := a.graph(fn)
	if g == nil {
		return false
	}
	for _, chk := range fn.Calls {
		selected, ok := a.admitting(chk, valueID)
		if !ok {
			continue
		}
		if a.reachedThrough(g, sink.Block, chk.Block, selected) {
			return true
		}
	}
	return false
}

// definitionSelected is the shape where the decision picks which value is used:
//
//	if (isValidReturnToUrl(body.returnTo, domainConfig)) signInPage = body.returnTo;
//	else signInPage = concatUrls(getConfig().appBaseUrl, "signin");
//
// The two arms rejoin, so the SINK is not on the approved branch and never can be. What
// is on it is the assignment, and that is the thing to ask about.
func (a *admission) definitionSelected(from, to string) bool {
	fn := a.e.ix.OwnerOfValue[to]
	if fn == nil {
		return false
	}
	g := a.graph(fn)
	if g == nil {
		return false
	}
	for _, chk := range fn.Calls {
		selected, ok := a.admitting(chk, from)
		if !ok {
			continue
		}
		if a.everyClassifiedDefinitionSelected(to, g, chk.Block, selected) {
			return true
		}
	}
	return false
}

// everyClassifiedDefinitionSelected requires that no caller value reaches this variable
// from anywhere the decision did not allow.
//
// One assignment inside the approved branch and a second one outside it is not an
// approved value, and the witness path shows only one of the two -- the engine commits
// to a single predecessor per value. So the other definitions are looked for here rather
// than assumed absent.
func (a *admission) everyClassifiedDefinitionSelected(to string, g *cfg.Graph, branch string, selected int) bool {
	found := false
	for _, f := range a.e.flowEdgesInto[to] {
		if !a.e.tainted[f.From] {
			continue
		}
		// EMPTY IS A REFUSAL, never a default (see ir.Flow.Block). A hop the frontend
		// could not place cannot be shown to sit inside the approved branch.
		if f.Block == "" || !a.reachedThrough(g, f.Block, branch, selected) {
			return false
		}
		found = true
	}
	return found
}

// admitting returns which successor of this call's block the program takes when its
// decision about `valueID` came out YES, and whether such a decision was made at all.
func (a *admission) admitting(chk *ir.Call, valueID string) (int, bool) {
	if chk.Block == "" || chk.Callee.Kind != "local" || chk.Callee.FunctionID == "" {
		return 0, false
	}
	callee := a.e.ix.FuncByID[chk.Callee.FunctionID]
	if callee == nil {
		return 0, false
	}
	selected, ok := a.polarity(chk)
	if !ok {
		return 0, false
	}
	// The call must have been handed THIS value -- the same text, not merely a value the
	// same variable held at some other point in the function.
	decided := false
	for _, arg := range chk.Args {
		if arg.ValueID == "" || !a.sameExpression(arg.ValueID, valueID) {
			continue
		}
		for _, p := range arg.BoundParams(callee) {
			// A destructured binding receives a PART of the argument; a decision about
			// one field is not a decision about the value handed over.
			if p.Destructured {
				continue
			}
			if a.constrains(callee, p.ValueID) {
				decided = true
			}
		}
	}
	if !decided {
		return 0, false
	}
	return selected, true
}

// polarity says which successor of a call's block the program takes when the call
// answered YES.
//
// A language fact the graph cannot recover: `if (!check(x)) return` and `if (check(x))
// return` have identical blocks and opposite meanings. Two spellings carry it. The
// frontend states it directly where the call IS the condition (ir.Call.ConditionBranch).
// Where the call is one side of a CONJUNCTION -- `if (allowPartial && isAllowed(uri, x))`
// -- the branch is taken on the conjunction, and the frontend records the conjunction as
// a value it names `both`: entering its truthy successor means every operand was truthy,
// so it means this call was. A disjunction is deliberately not followed. Its truthy
// successor means SOME operand held, which is no statement about this one at all, and
// telling the two apart is exactly why the frontends name them differently.
func (a *admission) polarity(chk *ir.Call) (int, bool) {
	switch chk.ConditionBranch {
	case "truthy":
		return 0, true
	case "falsy":
		return 1, true
	}
	if chk.ResultID == "" {
		return 0, false
	}
	conjuncts := map[string]bool{chk.ResultID: true}
	for round := 0; round < 8; round++ {
		grew := false
		for id := range conjuncts {
			for _, f := range a.e.ix.FlowsFrom[id] {
				if f.Kind != "assign" || conjuncts[f.To] {
					continue
				}
				if v := a.e.ix.ValueByID[f.To]; v != nil && v.Name == "both" {
					conjuncts[f.To] = true
					grew = true
				}
			}
		}
		if !grew {
			break
		}
	}
	fn := a.e.ix.OwnerOfCall[chk.ID]
	if fn == nil {
		return 0, false
	}
	for _, cmp := range fn.Comparisons {
		if cmp.Op == "truthy" && cmp.Block == chk.Block && conjuncts[cmp.Left] {
			return 0, true
		}
	}
	return 0, false
}

// returnedConstrained reports whether a value came out of a function that answers only
// with data of its own or with the caller's value on the branch where it matched.
//
// The other half of the shape, and the half that does not need a guard at the call site.
// medplum's `getClientRedirectUri(client, params.redirect_uri)` answers with a registered
// URI, with the requested one, or with nothing -- and with the requested one only inside
// the branch that proved it shares an origin with a registered one. Whatever a caller of
// that function does with the answer, the answer is a destination the deployment
// registered.
//
// Every tainted return has to be accounted for, not merely one: a function with a second
// way out that hands the value back unexamined constrains nothing, and the witness path
// shows only the way out it happened to travel.
func (a *admission) returnedConstrained(resultID string) bool {
	c := a.e.callByResult[resultID]
	if c == nil || c.Callee.Kind != "local" || c.Callee.FunctionID == "" {
		return false
	}
	callee := a.e.ix.FuncByID[c.Callee.FunctionID]
	// A frontend that did not state where its returns left the function has not refused
	// to answer this question -- it has refused to be asked (see ir.Function.ReturnBlocks).
	if callee == nil || len(callee.Returns) == 0 || len(callee.ReturnBlocks) != len(callee.Returns) {
		return false
	}
	checked := map[string]bool{}
	for _, arg := range c.Args {
		if arg.ValueID == "" || !a.e.tainted[arg.ValueID] {
			continue
		}
		for _, p := range arg.BoundParams(callee) {
			if !p.Destructured {
				checked[p.ValueID] = true
			}
		}
	}
	if len(checked) == 0 {
		return false
	}
	g := a.graph(callee)
	if g == nil {
		return false
	}
	accounted := false
	for i, r := range callee.Returns {
		if !a.e.tainted[r] {
			continue
		}
		if !a.returnAdmitted(callee, g, r, callee.ReturnBlocks[i], checked) {
			return false
		}
		accounted = true
	}
	return accounted
}

// returnAdmitted accounts for one way out of a checking function.
//
// Either the value handed back is the program's own -- `return uri`, a member of the
// registered list -- or it is the caller's, in which case it may leave only through a
// branch the program took because its decision about that value came out YES.
func (a *admission) returnAdmitted(callee *ir.Function, g *cfg.Graph, r, block string, checked map[string]bool) bool {
	if a.programsOwnData(r) {
		return true
	}
	if block == "" {
		return false
	}
	for param := range checked {
		if !a.reachesFrom(param, r) {
			continue
		}
		for _, chk := range callee.Calls {
			selected, ok := a.admitting(chk, param)
			if !ok {
				continue
			}
			if a.reachedThrough(g, block, chk.Block, selected) {
				return true
			}
		}
	}
	return false
}

// reachesFrom reports whether the classification of `to` came from `from`, following the
// witness the engine committed to.
func (a *admission) reachesFrom(from, to string) bool {
	seen := map[string]bool{}
	for cur := to; cur != "" && !seen[cur]; {
		if cur == from {
			return true
		}
		seen[cur] = true
		ed, ok := a.e.pred[cur]
		if !ok {
			return false
		}
		cur = ed.from
	}
	return false
}

// constrains reports whether this function's answer is decided by comparing the value it
// was handed -- or the part of it this sink turns on -- against data the program owns.
func (a *admission) constrains(callee *ir.Function, paramValueID string) bool {
	key := callee.ID + "\x00" + paramValueID
	if known, ok := a.decides[key]; ok {
		return known
	}
	// A function that reaches itself proves nothing about itself.
	a.decides[key] = false
	decided := a.decidesOnEquality(callee, paramValueID)
	a.decides[key] = decided
	return decided
}

func (a *admission) decidesOnEquality(callee *ir.Function, paramValueID string) bool {
	family := a.family(callee)
	derived := a.derivedFrom(family, paramValueID)
	for _, fn := range family {
		for _, cmp := range fn.Comparisons {
			if !equalityOperator(cmp.Op) {
				continue
			}
			mine, theirs := cmp.Left, cmp.Right
			if !derived[mine] {
				mine, theirs = cmp.Right, cmp.Left
			}
			if !derived[mine] || derived[theirs] {
				continue
			}
			if !a.programsOwnData(theirs) {
				continue
			}
			if !contains(a.parts, leafOf(a.e.ix.ValueByID[mine])) {
				continue
			}
			if !a.settlesAnswer(fn, cmp.Block) {
				continue
			}
			return true
		}
	}
	return false
}

// settlesAnswer reports whether the block holding a comparison is one where the
// function's answer is decided rather than merely observed.
//
// Two spellings, because predicates are written both ways. `if (uri === requested)
// return uri;` puts the comparison in a guard, one side of which leaves the function.
// `return a.protocol === b.protocol && a.hostname === b.hostname;` puts it in a block
// that ends by returning. A comparison in neither -- one whose result is dropped, or
// which decides only a log line -- is an aside and does not speak for the function.
func (a *admission) settlesAnswer(fn *ir.Function, block string) bool {
	if block == "" {
		return false
	}
	if g := a.graph(fn); g != nil && g.IsGuard(block) {
		return true
	}
	for _, b := range fn.Blocks {
		if b.ID == block {
			return b.Terminator == "return"
		}
	}
	return false
}

// family is the callee together with the functions it hands to its own calls.
//
// A predicate written for `some`, `every` or `find` lives in a nested function, and the
// frontend resolves an outer binding to the value the outer function defined -- so
// `returnToUrl.hostname === allowed.hostname` inside the callback is already an edge
// from the enclosing function's `returnToUrl`. Reading the two bodies as one is
// therefore not an approximation; it is how the IR already spells them.
//
// One level only. A predicate two frames down is a different claim, and this one is
// about the function whose answer the call site branched on.
func (a *admission) family(callee *ir.Function) []*ir.Function {
	out := []*ir.Function{callee}
	seen := map[string]bool{callee.ID: true}
	for _, c := range callee.Calls {
		for _, arg := range c.Args {
			if arg.FunctionID == "" || seen[arg.FunctionID] {
				continue
			}
			if fn := a.e.ix.FuncByID[arg.FunctionID]; fn != nil {
				seen[fn.ID] = true
				out = append(out, fn)
			}
		}
	}
	return out
}

// derivedFrom closes over the values these functions compute FROM the checked one, so
// that `new URL(returnTo).hostname` is recognised as a part of `returnTo`.
func (a *admission) derivedFrom(family []*ir.Function, root string) map[string]bool {
	derived := map[string]bool{root: true}
	for round := 0; round < 8; round++ {
		grew := false
		for _, fn := range family {
			for _, f := range fn.Flows {
				if derived[f.From] && !derived[f.To] {
					derived[f.To] = true
					grew = true
				}
			}
			for _, c := range fn.Calls {
				if c.ResultID == "" || derived[c.ResultID] {
					continue
				}
				carries := derived[c.ReceiverID]
				for _, arg := range c.Args {
					carries = carries || derived[arg.ValueID]
				}
				if carries {
					derived[c.ResultID] = true
					grew = true
				}
			}
		}
		if !grew {
			break
		}
	}
	return derived
}

// sameExpression reports whether two values are the same text written twice.
//
// `body.returnTo` on the line that tests it and `body.returnTo` on the line that uses it
// are separate nodes, because each read is its own value. A decision about one of them
// is a decision about the other, and refusing to say so would leave the shape real code
// is written in -- test the field, then use the field -- outside every proof.
func (a *admission) sameExpression(x, y string) bool {
	if x == y {
		return true
	}
	ex, ey := a.expressionOf(x), a.expressionOf(y)
	return ex.known && ey.known && ex.root == ey.root && ex.path == ey.path
}

// expressionOf walks a value back through the hops a re-read of the same text produces:
// a rename, and a property read. Anything else -- a call, a composition, a merge of two
// definitions -- ends the walk, because what comes out of those is not a re-read.
func (a *admission) expressionOf(id string) expression {
	if e, ok := a.exprs[id]; ok {
		return e
	}
	a.exprs[id] = expression{}
	path := ""
	seen := map[string]bool{}
	cur := id
	for hops := 0; hops < 16 && cur != "" && !seen[cur]; hops++ {
		seen[cur] = true
		edges := a.e.flowEdgesInto[cur]
		if len(edges) != 1 {
			// No definition at all is a root: a parameter, a global, a literal. Several
			// is a merge, and a merge is not one expression.
			if len(edges) == 0 {
				e := expression{root: cur, path: path, known: true}
				a.exprs[id] = e
				return e
			}
			break
		}
		switch edges[0].Kind {
		case "assign":
		case "property":
			v := a.e.ix.ValueByID[cur]
			if v == nil || v.Path == "" {
				return a.exprs[id]
			}
			path = v.Path + "\x00" + path
		default:
			e := expression{root: cur, path: path, known: true}
			a.exprs[id] = e
			return e
		}
		cur = edges[0].From
	}
	return a.exprs[id]
}

// programsOwnData reports whether this side of a comparison is data the PROGRAM holds
// rather than text the caller sent. It is the whole difference between an allow-list and
// a coincidence, so it is stated as two refusals and one positive.
//
// A literal written at the comparison is refused. It is a constant in an expression, not
// a set anybody registered, and admitting one would make `x === ""` read as an
// allow-list.
//
// A value the caller can also reach is refused. `f(a, b) { return a === b }` handed two
// fields of one request decides nothing at all, and a program that compares one caller
// string against another has not consulted anything of its own.
//
// What is accepted besides unclassified data is an ELEMENT OF A COLLECTION whose own
// classification rests on an assumption rather than on evidence. That combination is the
// measured case and neither half of it is decoration. medplum's allow-list is
// `domainConfig.allowedPostLoginRedirectUrls`, and the engine calls it caller data
// because the caller named which domain to look up -- `getDomainConfiguration(body.domain)`
// is a call whose body is not in the tree, so the taint crossing it is a presumption the
// engine already records as one (see Finding.Assumptions). The contents of that list were
// written by whoever configured the deployment. Requiring the collection instead of
// accepting any assumed value keeps `f(req.x, transform(req.y))` out; requiring the
// assumption instead of accepting any collection keeps out the way a caller actually can
// supply the list -- sending it in the request, where the chain is property reads the
// engine followed end to end, or storing it earlier, where the chain begins at a store
// read the engine seeded. testdata/registered-destination holds that case as a positive.
//
// The limit, stated rather than hidden: if the unresolved call is a pure transform of the
// caller's own bytes rather than a lookup -- `JSON.parse(req.body.allowed)` -- the
// collection really is the caller's and this says otherwise. Reading that apart needs the
// callee's body, which is the same thing every other judgement here needs and does not
// have; what bounds the cost is that the value must ALSO be compared for equality, in a
// block that settles the function's answer, on the branch the sink is reached from.
func (a *admission) programsOwnData(id string) bool {
	v := a.e.ix.ValueByID[id]
	if v == nil || v.Kind == ir.ValueLiteral {
		return false
	}
	if !a.e.tainted[id] {
		return true
	}
	collection, ok := a.collectionBehind(id)
	return ok && a.restsOnAnAssumption(collection)
}

// collectionBehind names the collection an element was taken out of, following the value
// back through whatever the program computed from it.
func (a *admission) collectionBehind(id string) (string, bool) {
	seen := map[string]bool{}
	for cur := id; cur != "" && !seen[cur]; {
		seen[cur] = true
		if collection, ok := a.elementOf(cur); ok {
			return collection, true
		}
		ed, ok := a.e.pred[cur]
		if !ok {
			return "", false
		}
		cur = ed.from
	}
	return "", false
}

// elementOf reports the collection this value is one member of, in the two spellings the
// IR gives an iteration.
//
// A callback the model calls an element binding is the first: `list.some(u => ...)` binds
// each member to the callback's parameter, and the model already says which methods do
// that and which parameter receives it. A for-of binding is the second: the frontend
// records the iterated expression on the loop header as its bound, so the member and the
// collection are joined without reading any name.
func (a *admission) elementOf(id string) (string, bool) {
	fn := a.e.ix.OwnerOfValue[id]
	if fn == nil {
		return "", false
	}
	for _, p := range fn.Params {
		if p.ValueID != id {
			continue
		}
		for _, c := range a.e.ix.PassedAt[fn.ID] {
			rule, ok := a.e.m.CallbackFor(c.Method)
			if !ok || rule.Note != "element" || c.ReceiverID == "" {
				continue
			}
			if arg, found := argAt(c, rule.CallbackArg); found && arg.FunctionID == fn.ID && p.Index == rule.CallbackParam {
				return c.ReceiverID, true
			}
		}
	}
	edges := a.e.flowEdgesInto[id]
	if len(edges) != 1 || edges[0].Kind != "property" {
		return "", false
	}
	for _, b := range fn.Blocks {
		if b.LoopHeader && b.LoopBound != "" && b.LoopBound == edges[0].From {
			return edges[0].From, true
		}
	}
	return "", false
}

// restsOnAnAssumption reports whether this value carries its classification only because
// the engine took a call it could not see into at its word.
func (a *admission) restsOnAnAssumption(id string) bool {
	seen := map[string]bool{}
	for cur := id; cur != "" && !seen[cur]; {
		seen[cur] = true
		ed, ok := a.e.pred[cur]
		if !ok {
			return false
		}
		if ed.assumed {
			return true
		}
		cur = ed.from
	}
	return false
}

// reachedThrough reports that a position in the graph is arrived at by taking one named
// arm of a branch.
//
// Two questions, because one of them alone answers the shapes real code is written in and
// the other does not. SelectedBySuccessor asks whether the position is REACHABLE only
// through that arm, which is exact and which a loop defeats: `for (...) { if (ok) return
// x; }` reaches the return from the other arm too, on the next iteration, and every
// allow-list written as a search over a list is that shape. DependsOnSuccessor asks
// whether the position sits ON that arm and on no other, which is what survives a back
// edge. A position that satisfies either was arrived at by the program answering yes.
func (a *admission) reachedThrough(g *cfg.Graph, target, branch string, selected int) bool {
	if g == nil || target == "" || branch == "" {
		return false
	}
	if g.SelectedBySuccessor(target, branch, selected) {
		return true
	}
	// DependsOnSuccessor does not require the block to branch at all, and "reached
	// through the only arm" is not a decision about anything.
	return g.BranchesTwoWays(branch) && g.DependsOnSuccessor(target, branch, selected)
}

func (a *admission) graph(fn *ir.Function) *cfg.Graph {
	if g, ok := a.graphs[fn.ID]; ok {
		return g
	}
	g := cfg.Build(fn)
	a.graphs[fn.ID] = g
	return g
}

// equalityOperator is the whole set: a comparison that admits a value must say the value
// IS one the program knows. An ordering or a containment says something weaker, and
// `!==` is the same statement written the other way round -- which is why it is absent:
// the branch it selects is the one where the value did NOT match.
func equalityOperator(op string) bool {
	switch op {
	case "===", "==", "Is", "Eq":
		return true
	default:
		return false
	}
}

// leafOf names the part of a value a comparison was taken of: the last segment of the
// path read off it, or "" for the value itself.
func leafOf(v *ir.Value) string {
	if v == nil {
		return ""
	}
	path := v.Path
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[i+1:]
		}
	}
	return path
}
