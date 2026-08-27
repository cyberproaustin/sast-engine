// Package store finds weaknesses in what got WRITTEN somewhere.
//
// The engine's fifth analysis kind, and like the fourth it exists because a real weakness
// has no call and no comparison in it. `req.session.role = req.body.role` calls nothing
// and compares nothing: the caller's claim is moved to the far side of a trust boundary,
// and everything downstream that reads the session gets it back looking like state the
// server established.
//
// The IR recorded assignments to plain names and nothing else until this needed them, so
// a write into a property or a subscript was invisible -- which is to say the weakness was
// not merely unbuilt but unexpressible.
package store

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/literal"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// Analyze reports classified values written into a named destination.
func Analyze(d *ir.IR, m model.Model, byClass map[string]taint.Classified) []taint.Finding {
	if len(m.Stores) == 0 {
		return nil
	}
	ix := ir.NewIndex(d)
	rot := newRotation(d, ix)
	elements := elementParams(d, ix)
	doms := newDominance()
	containers := boundedContainers(d, ix)
	flowsInto := make(map[string][]ir.Flow)
	callByResult := make(map[string]*ir.Call)
	for _, fn := range d.Functions {
		for _, f := range fn.Flows {
			flowsInto[f.To] = append(flowsInto[f.To], f)
		}
		for _, c := range fn.Calls {
			if c.ResultID != "" {
				callByResult[c.ResultID] = c
			}
		}
	}

	var out []taint.Finding
	for _, fn := range d.Functions {
		servesRequest := reachedFromEntry(ix, fn)
		for _, w := range fn.Writes {
			if w.From == "" {
				continue
			}
			for _, rule := range m.Stores {
				// "Did this value come from a request" and "did this line run while
				// serving one" are different questions, and only the second one makes a
				// write into shared state a cross-request leak.
				if rule.RequiresEntryFunction && !servesRequest {
					continue
				}
				if rule.IntoScope != "" {
					if w.Scope != rule.IntoScope {
						continue
					}
				} else if !intoMatches(ix, w, rule) {
					continue
				}
				if len(rule.NotInto) > 0 && intoMatches(ix, w, model.StoreRule{Into: rule.NotInto}) {
					continue
				}
				if len(rule.Path) > 0 && !pathMatches(w.Path, rule.Path) {
					continue
				}
				if pathMatches(w.Path, rule.NotPath) {
					continue
				}
				if len(rule.PathContains) > 0 &&
					(containsWord(w.Path, rule.PathExcept) || !containsWord(w.Path, rule.PathContains)) {
					continue
				}
				if rule.NotElement && elements[w.Base] {
					continue
				}
				if v := ix.ValueByID[w.From]; v != nil && v.Kind == ir.ValueLiteral &&
					pathMatches(strings.TrimSpace(v.Literal), rule.NotFrom) {
					continue
				}
				// A rule whose subject is the KEY reads a different half of the same
				// statement: not what was filed, but what it was filed under, because
				// that is what decides how large the container can become.
				if rule.KeyClass != "" {
					f, ok := retention(ix, doms, containers, fn, w, rule, byClass[rule.KeyClass])
					if ok {
						out = append(out, f)
					}
					continue
				}
				// A rule about what did NOT happen beside the write needs no
				// classification either: the write is the event.
				if len(rule.AbsentCall) > 0 {
					if rot.reaches(fn.ID, rule.AbsentCall) {
						continue
					}
					out = append(out, finding(ix, fn, w, rule, taint.Origin{Label: writtenLabel(ix, w)}))
					continue
				}
				// A rule about what was WRITTEN DOWN needs no classification: being a
				// literal is the defect, and a value read from the environment is not one.
				if rule.FromLiteral {
					v := ix.ValueByID[w.From]
					// The same bar the literal analysis applies, for the same reason
					// and in the same place: a fixture is not a leak, and a REAL key
					// committed to a test is. `cookie_secret = "abc123"` inside
					// jupyterhub/tests is somebody making a test pass.
					if v != nil && v.Kind == ir.ValueLiteral && ix.InTestModule(w.Loc) &&
						literal.IsPlaceholder(strings.TrimSpace(v.Literal)) {
						continue
					}
					if v == nil || v.Kind != ir.ValueLiteral || !meaningfulSecret(v.Literal) {
						continue
					}
					out = append(out, finding(ix, fn, w, rule, taint.Origin{Label: quoted(v.Literal)}))
					continue
				}
				carrying := byClass[rule.Class]
				if !carrying.Values[w.From] {
					continue
				}
				composed := composedOnClassifiedPath(w.From, flowsInto, carrying.Values, map[string]bool{}, 0)
				if rule.RequiresComposition && !composed {
					continue
				}
				if rule.RequiresWholeValue && composed {
					continue
				}
				if rule.Context != "" && !unsanitizedClassifiedPath(m, w.From, rule.Context, carrying, flowsInto, callByResult, map[string]bool{}, 0) {
					continue
				}
				// A field read out of something the classification reached is not the
				// classified thing. A server-side lookup handed a request once does not
				// make its answer the caller's.
				if rule.RequiresUnprojected && carrying.Projected[w.From] {
					continue
				}
				out = append(out, finding(ix, fn, w, rule, carrying.Origin[w.From]))
			}
		}
	}
	return out
}

// composedOnClassifiedPath asks whether the caller's contribution crossed a string
// composition on its way to a write. Literal siblings are deliberately ignored: they
// establish that composition happened, while only the classified branch establishes
// which part the caller supplied.
func composedOnClassifiedPath(id string, into map[string][]ir.Flow, classified map[string]bool, seen map[string]bool, depth int) bool {
	if id == "" || depth >= 16 || seen[id] {
		return false
	}
	seen[id] = true
	defer delete(seen, id)
	for _, f := range into[id] {
		if !classified[f.From] {
			continue
		}
		if f.Kind == "binary" || f.Kind == "template" {
			return true
		}
		if composedOnClassifiedPath(f.From, into, classified, seen, depth+1) {
			return true
		}
	}
	return false
}

// unsanitizedClassifiedPath is the assignment-side mirror of taint.buildFinding's
// sanitizer walk. Every classified predecessor must be neutralized; one unencoded path
// keeps the finding, which is the precision-preserving direction at a merged value.
func unsanitizedClassifiedPath(m model.Model, id, context string, carrying taint.Classified, into map[string][]ir.Flow, callByResult map[string]*ir.Call, seen map[string]bool, depth int) bool {
	if id == "" || depth >= 16 || seen[id] {
		return true
	}
	if carrying.Seeds[id] {
		return true
	}
	seen[id] = true
	defer delete(seen, id)
	if c := callByResult[id]; c != nil {
		if s, ok := m.SanitizerFor(c.Callee.Symbol); ok && s.AppliesTo("untrusted-input") && s.Clears(context) && sanitizerCoversClassifiedInputs(s, c, carrying.Values) {
			return false
		}
	}
	found := false
	for _, f := range into[id] {
		if !carrying.Values[f.From] {
			continue
		}
		found = true
		if unsanitizedClassifiedPath(m, f.From, context, carrying, into, callByResult, seen, depth+1) {
			return true
		}
	}
	return !found
}

// sanitizerCoversClassifiedInputs prevents an argument-specific transform from clearing
// a dangerous value arriving through a different argument. If both the URL and its query
// mapping are classified, url_concat has made only the latter safe and the former keeps
// the finding alive.
func sanitizerCoversClassifiedInputs(s model.SanitizerRule, c *ir.Call, classified map[string]bool) bool {
	if s.RequiresInputArg == nil {
		return true
	}
	covered := false
	for _, a := range c.Args {
		if !classified[a.ValueID] {
			continue
		}
		if a.Index != *s.RequiresInputArg {
			return false
		}
		covered = true
	}
	return covered
}

// reachedFromEntry reports whether a function is a request handler or is called by one,
// within a few hops. Bounded on purpose: past three calls the answer stops being evidence
// that this line runs per-request and starts being evidence that the program is connected.
func reachedFromEntry(ix *ir.Index, fn *ir.Function) bool {
	seen := map[string]bool{fn.ID: true}
	frontier := []*ir.Function{fn}
	// The function itself and its DIRECT callers, and no further. The limit is a
	// measurement rather than a preference: at three hops the answer stopped being
	// evidence that this line runs per-request and started being evidence that the
	// program is connected, and narrowing it removed five findings from one production
	// repository that were an allow-list, a strategy table and a sanitiser configuration
	// assembled at startup from a hook a route also calls.
	const hops = 2
	for depth := 0; depth < hops && len(frontier) > 0; depth++ {
		var next []*ir.Function
		for _, f := range frontier {
			if _, ok := ix.EntryByFunc[f.ID]; ok {
				return true
			}
			// Nothing is queued on the last pass, because nothing would look at it.
			if depth == hops-1 {
				continue
			}
			for _, site := range ix.CallSitesOf[f.ID] {
				caller := ix.OwnerOfCall[site.ID]
				if caller == nil || seen[caller.ID] {
					continue
				}
				seen[caller.ID] = true
				next = append(next, caller)
			}
		}
		frontier = next
	}
	return false
}

// intoMatches asks what is being written INTO, by the last segment of the base's access
// path. `req.session` and `request.session` are both a session, and which parameter the
// framework happened to hand it on is not the question.
func intoMatches(ix *ir.Index, w ir.Write, rule model.StoreRule) bool {
	base := ix.ValueByID[w.Base]
	if base == nil {
		return false
	}
	name := base.Path
	if name == "" {
		name = base.Name
	}
	if i := lastDot(name); i >= 0 {
		name = name[i+1:]
	}
	// A rule that names no destination is about the FIELD rather than the object holding
	// it. `user.role = req.body.role` and `account.isAdmin = req.body.isAdmin` are the
	// same weakness written on two different records, and enumerating what a record can
	// be called would be a list that is wrong the moment somebody names one differently.
	if len(rule.Into) == 0 {
		return true
	}
	for _, want := range rule.Into {
		if name == want {
			return true
		}
	}
	return false
}

// pathMatches narrows to particular keys written into a destination. The environment
// holds a hundred harmless variables and a few that decide where the next program comes
// from.
//
// Compared on the LAST segment and ignoring separators, so `is_admin`, `isAdmin` and
// `user.isAdmin` are one name. The source rules already read field names this way, and a
// rule that read them differently on the way in and on the way out would be two rules
// wearing one name.
func pathMatches(path string, want []string) bool {
	leaf := path
	if i := lastDot(leaf); i >= 0 {
		leaf = leaf[i+1:]
	}
	bare := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(leaf))
	for _, w := range want {
		if path == w || bare == strings.ToLower(w) {
			return true
		}
	}
	return false
}

// containsWord reports whether an access path contains one of these words, ignoring case
// and separators, so `SECRET_KEY_HMAC` and `secretKey` both contain `secret`.
func containsWord(path string, words []string) bool {
	lower := strings.ToLower(path)
	for _, w := range words {
		if strings.Contains(lower, strings.ToLower(w)) {
			return true
		}
	}
	return false
}

// rotation answers whether a function is anywhere near a particular call.
//
// "Anywhere near" is four directions, and each of them was a false positive on the clean
// corpus before it was added: the calls the function makes; the functions it hands to
// something else, because `new Promise((resolve) => req.session.regenerate(...))` is how
// this is written in practice; the local helpers it calls, because a rotation is routinely
// named `regenerateSessionPreservingData` and lives elsewhere; and its own callers,
// because the rotation is often in the route and the assignment in the helper the route
// calls.
//
// Deliberately generous in every direction. A missing call is an argument from silence,
// and an argument from silence has to be quiet whenever there is any reason to be.
type rotation struct {
	methods map[string]map[string]bool // function -> lowercased methods it calls
	out     map[string][]string        // function -> functions it passes on or calls
	callers map[string][]string
	isEntry map[string]bool
}

func newRotation(d *ir.IR, ix *ir.Index) *rotation {
	r := &rotation{
		methods: map[string]map[string]bool{},
		out:     map[string][]string{},
		callers: map[string][]string{},
		isEntry: map[string]bool{},
	}
	for id := range ix.EntryByFunc {
		r.isEntry[id] = true
	}
	for _, fn := range d.Functions {
		called := map[string]bool{}
		for _, c := range fn.Calls {
			if c.Method != "" {
				called[strings.ToLower(c.Method)] = true
			}
			if sym := c.Callee.Symbol; sym != "" {
				if j := lastDot(sym); j >= 0 {
					sym = sym[j+1:]
				}
				called[strings.ToLower(sym)] = true
			}
			for _, a := range c.Args {
				if a.FunctionID != "" {
					r.out[fn.ID] = append(r.out[fn.ID], a.FunctionID)
					// And the reverse. `req.session.regenerate(() => { ... })` puts the
					// rotation in the OUTER function and the assignment in the callback,
					// so a callback has to be able to see out of itself.
					r.callers[a.FunctionID] = append(r.callers[a.FunctionID], fn.ID)
				}
			}
			if id := c.Callee.FunctionID; id != "" {
				r.out[fn.ID] = append(r.out[fn.ID], id)
				r.callers[id] = append(r.callers[id], fn.ID)
			}
		}
		r.methods[fn.ID] = called
	}
	return r
}

// reaches reports whether any of these calls is made by this function, by anything it
// reaches, or by a caller of it.
//
// Down and up are not symmetric, and one measurement is why. Descending from a function
// finds the promise executor and the named helper that do the rotation. Ascending finds
// the route that rotates before calling the helper that assigns. But ascending and then
// descending again finds a SIBLING -- another route registered on the same module, which
// has nothing to do with this one -- so an ascent stops at an entry point. A request
// begins at its handler, and whatever the module around it does is not part of it.
func (r *rotation) reaches(id string, want []string) bool {
	if r.down(id, want, map[string]bool{}, 3) {
		return true
	}
	seen := map[string]bool{id: true}
	frontier := []string{id}
	for depth := 0; depth < 2 && len(frontier) > 0; depth++ {
		var next []string
		for _, f := range frontier {
			if r.isEntry[f] {
				continue
			}
			for _, c := range r.callers[f] {
				if seen[c] {
					continue
				}
				seen[c] = true
				if r.down(c, want, map[string]bool{}, 3) {
					return true
				}
				next = append(next, c)
			}
		}
		frontier = next
	}
	return false
}

func (r *rotation) down(id string, want []string, seen map[string]bool, depth int) bool {
	if depth < 0 || seen[id] {
		return false
	}
	seen[id] = true
	for _, w := range want {
		if r.methods[id][strings.ToLower(w)] {
			return true
		}
	}
	for _, n := range r.out[id] {
		if r.down(n, want, seen, depth-1) {
			return true
		}
	}
	return false
}

// elementParams collects the values bound to an ELEMENT of a collection: the first
// parameter of a callback passed to one of the iteration methods, and the variable a
// for-of loop binds. What a loop writes to is not the caller's own anything.
//
// The second half became necessary the moment loop variables started carrying what their
// collection carried. `for (const session of sessions) session.userId = id` is an
// administrative page updating other people's sessions, and it reads exactly like a login
// until you notice the loop.
func elementParams(d *ir.IR, ix *ir.Index) map[string]bool {
	over := map[string]bool{"foreach": true, "map": true, "filter": true, "find": true,
		"flatmap": true, "some": true, "every": true}
	out := map[string]bool{}
	for _, fn := range d.Functions {
		for _, c := range fn.Calls {
			if !over[strings.ToLower(c.Method)] {
				continue
			}
			for _, a := range c.Args {
				cb := ix.FuncByID[a.FunctionID]
				if cb != nil && len(cb.Params) > 0 {
					out[cb.Params[0].ValueID] = true
				}
			}
		}
	}
	// The loop form. A value reached only by a `property` flow out of something a
	// program iterates is an element of it, and the frontends lower a for-of binding
	// exactly that way.
	for _, fn := range d.Functions {
		for _, f := range fn.Flows {
			if f.Kind != "property" || f.To == "" {
				continue
			}
			if v := ix.ValueByID[f.To]; v != nil && v.Path == "" && v.Name != "" {
				// A property read with no PATH is not `x.field` -- the frontends always
				// record a path for those. It is a binding that took its value out of
				// something, which is what a loop variable is.
				out[f.To] = true
			}
		}
	}
	return out
}

// writtenLabel names what was written, for a rule whose finding is about the write having
// happened at all.
func writtenLabel(ix *ir.Index, w ir.Write) string {
	v := ix.ValueByID[w.From]
	switch {
	case v == nil:
		return w.Path
	case v.Kind == ir.ValueLiteral:
		return quoted(v.Literal)
	case v.Path != "":
		return v.Path
	case v.Name != "":
		return v.Name
	}
	return w.Path
}

// meaningfulSecret rejects the values that are a placeholder rather than a key. A config
// key set to None, to the empty string or to a flag is a key that is not set.
func meaningfulSecret(literal string) bool {
	v := strings.TrimSpace(strings.ToLower(literal))
	switch v {
	case "", "none", "null", "true", "false", "0", "1", "undefined", "changeme":
		return false
	}
	if len(v) < 4 {
		return false
	}
	// A secret is one opaque run of characters. These three shapes are what a key-named
	// setting holds when it is NOT holding a key, and each was measured on the clean
	// corpus: an endpoint the credential is sent TO, a sentence explaining that a
	// credential is required, and the mask a value is replaced with before it is logged.
	if strings.Contains(v, "://") {
		return false
	}
	// A sentence, not a key. Three or more words is the line: a real key is one run of
	// characters and occasionally two, and a passphrase written into the source is still
	// short -- while "either password or private_key is required" is a validation message
	// being assigned, which is what this shape looks like in a settings schema. Measured on
	// the clean corpus, and deliberately not "contains a space": Flask's own documented
	// example secret key has one in it.
	if len(strings.Fields(v)) > 2 {
		return false
	}
	// The mask a value is replaced with before it is logged, which is the one literal a
	// secret-named setting holds precisely BECAUSE the real secret must not be there.
	//
	// Only the characters a mask is actually made of. Rejecting ANY repeated character
	// threw away `app.secret_key = "aaaa"`, which is a hardcoded secret and a bad one.
	if strings.ContainsAny(v[:1], "*x•.-_#") && strings.TrimLeft(v, v[:1]) == "" {
		return false
	}
	return true
}

func quoted(s string) string { return "\"" + s + "\"" }

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

func finding(ix *ir.Index, fn *ir.Function, w ir.Write, rule model.StoreRule, o taint.Origin) taint.Finding {
	return taint.Finding{
		Analysis:      rule.ID,
		DataClass:     rule.Class,
		ChannelID:     rule.ID,
		Class:         rule.Finding,
		CWE:           rule.CWE,
		Message:       rule.Reason,
		Confidence:    taint.High,
		SourceLoc:     w.Loc,
		SourceLabel:   o.Label,
		EntryPoint:    o.EntryPoint,
		EntryMethod:   o.Method,
		EntryPath:     o.Path,
		EntryAnchored: o.Anchored,
		EntryTrust:    o.Trust,
		InTestModule:  ix.InTestModule(w.Loc),
		SinkLoc:       w.Loc,
		SinkFunction:  fn.Name,
		SinkSymbol:    fmt.Sprintf("write to %s", w.Path),
		SinkArgIndex:  -1,
		SinkRational:  rule.Rationale,
		Path: []taint.Hop{{
			Loc:         w.Loc,
			Description: fmt.Sprintf("written into %s", w.Path),
			Resolution:  ir.Resolved,
		}},
	}
}

// --- Retention: how many entries the caller can make the process keep ----------------
//
// The same statement the rules above read for what was PUT somewhere, read for what it
// was put UNDER. A container gains one entry per distinct key, so the key is what decides
// how large it can become -- and a key the caller supplies has no ceiling the program set.

// dominance builds a function's control-flow graph once and keeps it. The judgement
// below asks about the same graph repeatedly -- once for the function holding the write
// and once for every caller of it -- and building it each time would be several answers
// to a question that has one.
type dominance struct{ byFn map[string]*cfg.Graph }

func newDominance() *dominance { return &dominance{byFn: make(map[string]*cfg.Graph)} }

func (d *dominance) of(fn *ir.Function) *cfg.Graph {
	if g, ok := d.byFn[fn.ID]; ok {
		return g
	}
	g := cfg.Build(fn)
	d.byFn[fn.ID] = g
	return g
}

// retention judges a write by the key it was filed under.
func retention(ix *ir.Index, doms *dominance, bounded map[string]bool, fn *ir.Function,
	w ir.Write, rule model.StoreRule, keys taint.Classified) (taint.Finding, bool) {
	// A literal key cannot make a container grow past the number of literals in the
	// program, so only a computed one is a key in the sense this rule means.
	if w.Key == "" || !keys.Values[w.Key] {
		return taint.Finding{}, false
	}
	// Said here rather than left to be filtered downstream, where it would still be
	// counted: a fixture that fills a map is not an attack surface, and the harness
	// that fills it is the test doing its job.
	if ix.InTestModule(w.Loc) {
		return taint.Finding{}, false
	}
	if rule.RequiresUnprojected && keys.Projected[w.Key] {
		return taint.Finding{}, false
	}
	container := containerName(ix, w.Base)
	if container == "" {
		return taint.Finding{}, false
	}
	if rule.IntoOutlivingRequest && !outlivesRequest(ix, fn, w) {
		return taint.Finding{}, false
	}
	if rule.AbsentSizeBound && bounded[container] {
		return taint.Finding{}, false
	}
	site, gated := afterLookup(ix, doms, fn, w, rule, keys)
	if rule.NotAfterLookup && gated {
		return taint.Finding{}, false
	}
	return keyFinding(ix, fn, w, rule, keys.Origin[w.Key], container, site), true
}

// outlivesRequest reports whether the destination is reached through a binding no
// request created.
//
// The property chain is followed to its root and the root answers it: a name the
// language provides, or one declared at a module's top level and reached from a function
// that is not the module. A container made inside the handler dies with the handler
// however many entries it gained, and the identical statement there means nothing.
func outlivesRequest(ix *ir.Index, fn *ir.Function, w ir.Write) bool {
	if w.Scope == "process" {
		return true
	}
	root := ix.ValueByID[w.Base]
	for root != nil && root.Base != "" {
		root = ix.ValueByID[root.Base]
	}
	if root == nil {
		return false
	}
	if root.Kind == ir.ValueGlobal {
		return true
	}
	owner := ix.OwnerOfValue[root.ID]
	return owner != nil && owner.ID != fn.ID && isModuleTop(owner)
}

// isModuleTop reports whether a function IS a module's top level. Both frontends lower
// one as a function so that every analysis sees it without learning a new shape, and
// both name it the same way.
func isModuleTop(fn *ir.Function) bool { return fn.Name == "<module>" }

// containerName is the destination as the program spells it: the chain of names from the
// binding the write reaches down to the property being indexed.
//
// An identity rather than a description. It is what lets a cap written in one function be
// matched against an insertion written in another, which is where a cap usually is.
//
// Not qualified by module, so two containers of the same name in two files are one name
// here and a cap on either suppresses both. Deliberate and one-directional: this feeds a
// rule reporting the ABSENCE of a bound, and an argument from silence has to be quiet
// whenever there is any reason to be, so the collision costs recall and never precision.
func containerName(ix *ir.Index, id string) string {
	var parts []string
	for v := ix.ValueByID[id]; v != nil; v = ix.ValueByID[v.Base] {
		if seg := nameOf(v); seg != "" {
			parts = append([]string{seg}, parts...)
		}
		if v.Base == "" {
			break
		}
	}
	return strings.Join(parts, ".")
}

// nameOf is what a value is called, ignoring an anonymous subscript -- `list[id]` and
// `list` are the same container and only one of them has a name.
func nameOf(v *ir.Value) string {
	seg := v.Path
	if seg == "" {
		seg = v.Name
	}
	if seg == "[index]" {
		return ""
	}
	return seg
}

// extentWords are how a program asks how large a container has become.
var extentWords = []string{"length", "size", "count", "len"}

// boundedContainers is every container whose extent the program measures against a
// number written into the source.
//
// Program-wide on purpose. `if (cache.size > 1000) evict()` is routinely written in a
// different function from the insertion it bounds, and a rule reporting the ABSENCE of a
// bound has to be quiet whenever there is any reason to be: an argument from silence is
// only worth making when nothing anywhere contradicts it.
func boundedContainers(d *ir.IR, ix *ir.Index) map[string]bool {
	resultOf := make(map[string]*ir.Call)
	for _, fn := range d.Functions {
		for _, c := range fn.Calls {
			if c.ResultID != "" {
				resultOf[c.ResultID] = c
			}
		}
	}
	out := make(map[string]bool)
	for _, fn := range d.Functions {
		for _, cmp := range fn.Comparisons {
			for _, side := range []string{cmp.Left, cmp.Right} {
				if name := extentOf(ix, resultOf, side); name != "" {
					out[name] = true
				}
			}
		}
	}
	return out
}

// extentOf names the container a compared value MEASURES, or nothing when the value is
// not a measurement. `cache.size`, `len(cache)` and `Object.keys(cache).length` are the
// three spellings, and the third is why a call has to be looked through.
func extentOf(ix *ir.Index, resultOf map[string]*ir.Call, id string) string {
	v := ix.ValueByID[id]
	if v == nil {
		return ""
	}
	if v.Kind == ir.ValueProperty && contains(extentWords, strings.ToLower(leafName(v))) {
		return throughCall(ix, resultOf, v.Base)
	}
	if v.Kind == ir.ValueCallResult {
		if c := resultOf[v.ID]; c != nil && contains(extentWords, strings.ToLower(lastSegment(calleeName(c)))) {
			if len(c.Args) > 0 {
				return throughCall(ix, resultOf, c.Args[0].ValueID)
			}
		}
	}
	return ""
}

// throughCall names what a value is, looking through one call: `Object.keys(cache)` is
// not a container and the thing it was handed is.
func throughCall(ix *ir.Index, resultOf map[string]*ir.Call, id string) string {
	if v := ix.ValueByID[id]; v != nil && v.Kind == ir.ValueCallResult {
		if c := resultOf[v.ID]; c != nil && len(c.Args) > 0 {
			return containerName(ix, c.Args[0].ValueID)
		}
	}
	return containerName(ix, id)
}

// afterLookup reports whether something already DECIDED that this key names a real
// thing before the write ran.
//
// A basic block is the whole evidence and there is no guessing in it. A block contains no
// branch, so a call in the same block as the write cannot have changed whether the write
// runs, however plainly it looks like a check; a call in a block that DOMINATES the
// write's is one whose answer control has already been through. Where the key arrived as
// a parameter the same question is asked of every caller, because the lookup and the
// insertion are routinely in different functions.
//
// A write whose position the frontend declined to state -- inside a loop body, inside a
// switch arm -- is one this judgement cannot be made about, and it is not made.
func afterLookup(ix *ir.Index, doms *dominance, fn *ir.Function, w ir.Write,
	rule model.StoreRule, keys taint.Classified) (*ir.Call, bool) {
	if w.Block == "" {
		return nil, true
	}
	related := relatedValues(fn, w.Key)
	g := doms.of(fn)
	for _, c := range fn.Calls {
		if c.Block == "" || c.Block == w.Block || !handed(c, related) || pureOfKey(c, rule) {
			continue
		}
		if g.Dominates(c.Block, w.Block) {
			return nil, true
		}
	}
	return ungatedCallSite(ix, doms, fn, related, rule, keys)
}

// ungatedCallSite asks the same question of the callers, for a key that arrived as a
// parameter: the caller chose it, so the lookup that would have rejected it may be there.
//
// Every call site has to be gated for the container to be bounded, and the FIRST one that
// is not is returned rather than a bare no. A value reaching a shared helper is tainted by
// every route that reaches it, and the route the taint analysis happens to name is not
// necessarily the route that installs an entry for anything: uptime-kuma's push endpoint
// looks its monitor up and refuses when there is none, and its badge endpoints do not.
// Reporting the first would send a reader to a handler with the guard right there in it.
func ungatedCallSite(ix *ir.Index, doms *dominance, fn *ir.Function, related map[string]bool,
	rule model.StoreRule, keys taint.Classified) (*ir.Call, bool) {
	idx := -1
	for _, p := range fn.Params {
		if related[p.ValueID] {
			idx = p.Index
			break
		}
	}
	if idx < 0 {
		return nil, false
	}
	var ungated []*ir.Call
	considered := 0
	for _, site := range ix.CallSitesOf[fn.ID] {
		caller := ix.OwnerOfCall[site.ID]
		if caller == nil || site.Block == "" {
			continue
		}
		passed := ""
		for _, a := range site.Args {
			if a.Index == idx {
				passed = a.ValueID
			}
		}
		// A call site that hands over something the caller did NOT choose cannot make
		// the container grow with traffic, whatever it does or does not check first.
		// uptime-kuma's heartbeat loop passes a monitor its own scheduler owns.
		if passed == "" || !keys.Values[passed] {
			continue
		}
		considered++
		callerRelated := relatedValues(caller, passed)
		g := doms.of(caller)
		gated := false
		for _, c := range caller.Calls {
			if c.ID == site.ID || c.Block == "" || c.Block == site.Block ||
				!handed(c, callerRelated) || pureOfKey(c, rule) {
				continue
			}
			if g.Dominates(c.Block, site.Block) {
				gated = true
				break
			}
		}
		if !gated {
			ungated = append(ungated, site)
		}
	}
	if considered == 0 {
		return nil, false
	}
	if len(ungated) == 0 {
		return nil, true
	}
	// An entry point among them is the one a reader should be sent to: it is where the
	// key is chosen, and every hop below it is the program passing it along. Ordered by
	// position after that, so the same program always reports the same line.
	sort.SliceStable(ungated, func(i, j int) bool {
		ei := ix.OwnerOfCall[ungated[i].ID] != nil && ix.EntryByFunc[ix.OwnerOfCall[ungated[i].ID].ID] != nil
		ej := ix.OwnerOfCall[ungated[j].ID] != nil && ix.EntryByFunc[ix.OwnerOfCall[ungated[j].ID].ID] != nil
		if ei != ej {
			return ei
		}
		if ungated[i].Loc.File != ungated[j].Loc.File {
			return ungated[i].Loc.File < ungated[j].Loc.File
		}
		return ungated[i].Loc.Line < ungated[j].Loc.Line
	})
	return ungated[0], false
}

// pureOfKey reports whether a call decides nothing about a key beyond its own text.
//
// Two ways to be sure of it and neither is a guess. A method on a type the LANGUAGE
// declares is being asked about a value it already holds -- `id.trim()`, `re.test(id)` --
// and the frontend states which receivers those are. And the conversions and predicates
// the language provides as free functions are named in the model, because they have no
// receiver to be judged by.
func pureOfKey(c *ir.Call, rule model.StoreRule) bool {
	if c.ReceiverTypeOrigin == "builtin" {
		return true
	}
	return contains(rule.KeyPure, lastSegment(calleeName(c)))
}

// relatedValues is the key and everything one assignment step away from it in either
// direction, so that a lookup handed `id` still counts when the write was spelled with
// the value that `id` was parsed out of.
func relatedValues(fn *ir.Function, key string) map[string]bool {
	out := map[string]bool{key: true}
	// Two passes, because a chain of two assignments is ordinary and a chain of ten is
	// the program being connected rather than the value being the same one.
	for i := 0; i < 2; i++ {
		for _, f := range fn.Flows {
			if out[f.From] || out[f.To] {
				out[f.From], out[f.To] = true, true
			}
		}
	}
	return out
}

// handed reports whether a call was given one of these values, as an argument or as the
// receiver it was invoked on.
func handed(c *ir.Call, values map[string]bool) bool {
	if values[c.ReceiverID] {
		return true
	}
	for _, a := range c.Args {
		if values[a.ValueID] {
			return true
		}
	}
	return false
}

func leafName(v *ir.Value) string {
	name := v.Path
	if name == "" {
		name = v.Name
	}
	if i := lastDot(name); i >= 0 {
		name = name[i+1:]
	}
	return name
}

func calleeName(c *ir.Call) string {
	if c.Method != "" {
		return c.Method
	}
	if c.Callee.Symbol != "" {
		return c.Callee.Symbol
	}
	return c.Callee.Name
}

func lastSegment(s string) string {
	if i := lastDot(s); i >= 0 {
		return s[i+1:]
	}
	return s
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func keyFinding(ix *ir.Index, fn *ir.Function, w ir.Write, rule model.StoreRule,
	o taint.Origin, container string, site *ir.Call) taint.Finding {
	f := taint.Finding{
		Analysis:      rule.ID,
		DataClass:     rule.KeyClass,
		ChannelID:     rule.ID,
		Class:         rule.Finding,
		CWE:           rule.CWE,
		Message:       rule.Reason,
		Confidence:    taint.High,
		SourceLoc:     w.Loc,
		SourceLabel:   o.Label,
		EntryPoint:    o.EntryPoint,
		EntryMethod:   o.Method,
		EntryPath:     o.Path,
		EntryAnchored: o.Anchored,
		EntryTrust:    o.Trust,
		InTestModule:  ix.InTestModule(w.Loc),
		SinkLoc:       w.Loc,
		SinkFunction:  fn.Name,
		SinkSymbol:    fmt.Sprintf("entry in %s", container),
		SinkArgIndex:  -1,
		SinkRational:  rule.Rationale,
	}
	// The call site that installs an entry before anything has decided the key names
	// something is named first, because it is where a reader has to look. It is also the
	// honest anchor: a helper is tainted by every route that reaches it, and the route
	// the flow analysis happens to name may be one that guards perfectly.
	if site != nil {
		if caller := ix.OwnerOfCall[site.ID]; caller != nil {
			f.Path = append(f.Path, taint.Hop{
				Loc:         site.Loc,
				Description: fmt.Sprintf("%s() is handed a key nothing has looked up yet", calleeName(site)),
				Resolution:  site.Callee.Resolution,
			})
			if ep := ix.EntryByFunc[caller.ID]; ep != nil {
				f.EntryPoint = entryLabel(ep)
				f.EntryMethod = ep.Detail["method"]
				f.EntryPath = ep.Detail["path"]
				f.EntryAnchored = true
				f.EntryTrust = ep.TrustLevel()
			}
		}
	}
	f.Path = append(f.Path, taint.Hop{
		Loc:         w.Loc,
		Description: fmt.Sprintf("filed in %s under a key the caller chose", container),
		Resolution:  ir.Resolved,
	})
	return f
}

// entryLabel is an entry point in the terms the rest of a report uses.
func entryLabel(ep *ir.EntryPoint) string {
	parts := make([]string, 0, 2)
	if m := ep.Detail["method"]; m != "" {
		parts = append(parts, m)
	}
	if p := ep.Detail["path"]; p != "" {
		parts = append(parts, p)
	}
	desc := strings.Join(parts, " ")
	if desc == "" {
		desc = ep.Kind
	}
	if ep.Framework != "" {
		desc += " [" + ep.Framework + "]"
	}
	return desc
}
