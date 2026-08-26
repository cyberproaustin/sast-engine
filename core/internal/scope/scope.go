// Package scope answers a question about the RELATION between two calls: which record
// an authorization check was about, and which record the operation it admitted touched.
//
// The engine's sixth analysis kind, and it exists because the five before it can only
// judge one thing at a time. A flow analysis asks where a value goes; a call-shape
// analysis asks what a call was handed; a decision analysis asks what a branch believed;
// a store analysis asks what got written; a guard analysis asks whether a refusal was
// obeyed. None of them can say "and it was a different key", because none of them has two
// calls in view at once.
//
// What it replaces is a presumption. The ownership policy in `model.go` permits a record
// operation when the handler relates the record to the caller, and it accepted "a call
// carrying actor identity happened here" as that relation -- the engine's own output says
// so: *a helper receiving actor identity is presumed to enforce*. A handler authorized
// against one key and writing to another satisfies that presumption perfectly. The
// permission call is right there, it carries `req.user`, and it is asking about something
// else:
//
//	const { projectId, strategyId } = req.body;                  // two keys, both the caller's
//	if (!await access.hasPermission(req.user, PERM, projectId))  // authorized for THIS one
//	    return res.status(403).send();
//	await this.removeFromStrategy(strategyId, ...);              // wrote to THAT one
//
// So the relation is stated rather than presumed. A gate scoped to a key admits
// operations on that key; an operation on a different key needs something tying the two
// -- a lookup carrying both, or a comparison between them. Existence is not one of them:
// `featureExists(name)` proves the row is there and says nothing about who owns it, and a
// call carrying only the unauthorized key relates it to nothing.
package scope

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// Analyze reports store writes performed outside the scope the handler's own
// authorization check established.
func Analyze(d *ir.IR, m model.Model, byClass map[string]taint.Classified) []taint.Finding {
	if len(m.Scopes) == 0 {
		return nil
	}
	ix := ir.NewIndex(d)

	var out []taint.Finding
	for _, rule := range m.Scopes {
		// A judgement about which check GATES which write cannot be made without a
		// control-flow graph, and a rule that cannot be evaluated reports nothing rather
		// than reporting a guess (ADR-003).
		if len(rule.Requires.Missing(d.Frontend.Capabilities)) > 0 {
			continue
		}
		identity := byClass[rule.IdentityClass]
		if len(identity.Values) == 0 {
			// A relation to the caller's identity cannot be judged where no identity is
			// observable, and reporting every write as unscoped would be a statement
			// about this engine's vocabulary rather than about the application
			// (ADR-003). The ownership policy already reports that as unevaluated.
			continue
		}
		for i := range d.EntryPoints {
			ep := &d.EntryPoints[i]
			fn := ix.FuncByID[ep.FunctionID]
			if fn == nil {
				continue
			}
			out = append(out, judge(ix, fn, ep, rule, identity)...)
		}
	}
	sortFindings(out)
	return out
}

// judge runs the relation over one handler.
//
// The whole judgement is confined to the entry point's own function, and deliberately.
// The two facts it needs -- that a check GATED this operation, and that the check asked
// about a different key -- are both control-flow facts about one body. Following them
// across a call boundary would mean deciding which caller's gate governs which callee's
// write, and a wrong answer there reports a handler for a check another handler makes.
func judge(ix *ir.Index, fn *ir.Function, ep *ir.EntryPoint, rule model.ScopeRule, identity taint.Classified) []taint.Finding {
	g := cfg.Build(fn)
	if g == nil {
		return nil
	}
	keys := requestKeys(fn, rule)
	if len(keys) == 0 {
		return nil
	}
	carries := propagate(fn, keys)

	// Every enforced check in the handler, taken together. A handler that asks two
	// questions -- `canCreateTeamWebsite(auth, teamId)` and `canCreateWebsite(auth)` --
	// has authorized the union of what they were about, and judging each one alone would
	// report the second for a key the first covered.
	var gates []*ir.Call
	scope := map[string]bool{}
	for _, c := range fn.Calls {
		if !carriesIdentity(c, identity) || !g.IsGuard(c.Block) {
			continue
		}
		gates = append(gates, c)
		for _, a := range c.Args {
			if a.ValueID == "" || identity.Values[a.ValueID] {
				continue
			}
			for k := range carries[a.ValueID] {
				scope[k] = true
			}
		}
	}
	// A check handed no key at all is not scoped to a record: `requireRole(user,
	// "admin")` says something true about the caller and nothing about which row is
	// being touched, and this rule has no claim to make about it. That case stays with
	// the ownership policy, which asks the other question.
	if len(gates) == 0 || len(scope) == 0 {
		return nil
	}

	var out []taint.Finding
	// One finding per key, not per call. A handler that removes and then adds under the
	// same unauthorized identifier has made one mistake, and the second line teaches a
	// reader nothing the first did not.
	reported := map[string]bool{}

	for _, op := range fn.Calls {
		if !mutates(op, rule) || carriesIdentity(op, identity) {
			continue
		}
		gate := gatedBy(g, gates, op)
		if gate == nil {
			continue
		}
		for _, k := range unscoped(op, carries, scope) {
			if reported[k.id] {
				continue
			}
			// An identifier standing ALONGSIDE the authorized one, at the same depth,
			// is scoped by the call itself. `deleteSession(websiteId, sessionId)`
			// cannot reach a session of another website and `delete({where: {id,
			// projectId}})` cannot reach another project's row: the constraint is in
			// the selection rather than in a check above it, which is how multi-tenant
			// code is normally written.
			//
			// Depth is what makes that reading safe. An identifier written INTO the
			// record while the authorized one selects it is not constrained by
			// anything -- the row being updated is the one that was checked and the
			// field being set names a second one, which is precisely how a record gets
			// re-parented onto something nobody checked.
			if carriesScope(op, carries, scope, k.container) {
				continue
			}
			if related(g, fn, carries, k.id, scope, gates, op, rule, keys) {
				continue
			}
			if actorCompared(g, fn, identity, op) {
				continue
			}
			reported[k.id] = true
			out = append(out, finding(ix, fn, ep, rule, keys, k, scope, gate, op,
				anyScope(op, carries, scope)))
			break
		}
	}
	return out
}

// gatedBy returns a check the operation runs BECAUSE of: a branch one side of which
// leaves the handler, unavoidable on every path to the operation. Position alone would
// accept the rejection branch, which is where the refusal itself lives.
func gatedBy(g *cfg.Graph, gates []*ir.Call, op *ir.Call) *ir.Call {
	for _, gate := range gates {
		if gate.ID != op.ID && g.Dominates(gate.Block, op.Block) {
			return gate
		}
	}
	return nil
}

// actorCompared reports whether the handler tested the caller's identity in a branch it
// can leave from, on the way to this operation.
//
// A record fetched by the unauthorized key and then compared against the caller is an
// ownership check, and it relates the key to the caller directly rather than to the key
// the permission call named. The comparison is not required to mention the key: what it
// is compared against is a field of the row that was fetched, and a property read is
// deliberately not followed. This is the same test the ownership policy applies, and
// borrowing it keeps one shape from being clean under one rule and a finding under the
// other.
func actorCompared(g *cfg.Graph, fn *ir.Function, identity taint.Classified, op *ir.Call) bool {
	for _, cmp := range fn.Comparisons {
		if cmp.Block == "" || !g.IsGuard(cmp.Block) || !g.Dominates(cmp.Block, op.Block) {
			continue
		}
		if identity.Values[cmp.Left] || identity.Values[cmp.Right] {
			return true
		}
	}
	return false
}

// carriesScope reports whether the operation was also handed one of the keys the checks
// were about, at the given depth.
func carriesScope(op *ir.Call, carries map[string]map[string]string, scope map[string]bool, container string) bool {
	for _, a := range op.Args {
		for k, was := range carries[a.ValueID] {
			if scope[k] && was == container {
				return true
			}
		}
	}
	return false
}

// anyScope reports whether the operation was handed one of the authorized keys at all,
// wherever in the call it sits. That is what separates a write that REACHES another
// record from one that WRITES another record's identifier into the row it checked.
func anyScope(op *ir.Call, carries map[string]map[string]string, scope map[string]bool) bool {
	for _, a := range op.Args {
		for k := range carries[a.ValueID] {
			if scope[k] {
				return true
			}
		}
	}
	return false
}

// requestKey is a field of the request that names a record.
type requestKey struct {
	id string
	// name is how the handler spelled it, which is what a reader recognises.
	name string
	// container is where it was read from: `body`, `params`, the parameter itself.
	container string
	loc       ir.Loc
}

// requestKeys finds the fields of this handler's own request whose names say they are
// identifiers.
//
// Local to this analysis on purpose. Asking the taint engine instead would mean widening
// the untrusted-input classification to every framework whose routes are found by shape,
// which changes what forty other rules see; the question here is narrower than that and
// answerable from the handler's own values: a property read, off the request the framework
// handed in, whose last word is `id`.
func requestKeys(fn *ir.Function, rule model.ScopeRule) map[string]requestKey {
	values := make(map[string]*ir.Value, len(fn.Values))
	params := map[string]bool{}
	for i := range fn.Values {
		v := fn.Values[i]
		values[v.ID] = v
		if v.Kind == ir.ValueParam {
			params[v.ID] = true
		}
	}
	// The results of calls this handler made with one of its own parameters. A framework
	// that hands a handler a bare request gives it nowhere to put the parsed fields, so
	// they arrive as `const { body, query } = await parseRequest(request)` and the
	// container is one hop further out than usual.
	parsed := map[string]bool{}
	for i := range fn.Calls {
		c := fn.Calls[i]
		if c.ResultID == "" {
			continue
		}
		for _, a := range c.Args {
			if params[a.ValueID] {
				parsed[c.ResultID] = true
			}
		}
	}

	out := map[string]requestKey{}
	for i := range fn.Values {
		v := fn.Values[i]
		if v.Kind != ir.ValueProperty || v.Base == "" {
			continue
		}
		if !keyWord(leafOf(v), rule.KeyWords) {
			continue
		}
		container, ok := containerOf(values, params, parsed, v)
		if !ok {
			continue
		}
		out[v.ID] = requestKey{id: v.ID, name: leafOf(v), container: container, loc: v.Loc}
	}
	return out
}

// containerOf names where a property was read from, and reports whether that place is
// the request this handler was given. A value read off a local the handler computed is
// not a request key however it is spelled: `row.id` is the identifier of something the
// database returned, and the caller chose nothing about it.
func containerOf(values map[string]*ir.Value, params, parsed map[string]bool, v *ir.Value) (string, bool) {
	base := values[v.Base]
	if base == nil {
		return "", false
	}
	container := base.Name
	if base.Kind == ir.ValueProperty {
		container = leafOf(base)
	}
	if container == "" {
		container = "request"
	}
	// The chain has to reach the handler's own request. Bounded, because an IR is data
	// and this walks it.
	for cur, hops := base, 0; cur != nil && hops < 16; hops++ {
		if params[cur.ID] || parsed[cur.ID] {
			return container, true
		}
		if cur.Base == "" {
			return "", false
		}
		cur = values[cur.Base]
	}
	return "", false
}

// propagate carries key membership forward through the handler's own flows.
//
// Deliberately coarse in one direction and exact in the other. A value built out of a key
// carries it -- `report = await getReport(reportId)` is about that report, which is what
// makes the permission check on it a check about `reportId`. A value the key was read OUT
// of does not: `req.body` is not `req.body.projectId`, and treating a container as
// carrying everything inside it would let a handler that echoes the whole body count as
// relating every field in it.
//
// The map records one more thing than membership: whether the key became a FIELD of a
// structure on the way. `updateReport(reportId, { websiteId })` hands over one identifier
// and writes another one into the row, and those are different claims about the same
// call.
func propagate(fn *ir.Function, keys map[string]requestKey) map[string]map[string]string {
	carries := make(map[string]map[string]string, len(keys))
	add := func(to, key, container string) bool {
		if to == "" {
			return false
		}
		set, ok := carries[to]
		if !ok {
			set = map[string]string{}
			carries[to] = set
		}
		was, seen := set[key]
		// Direct displaces enclosed -- a value reached both ways is reached directly --
		// and between two containers the smaller name wins, so the answer does not
		// depend on the order the edges happen to be listed in.
		if seen && (was == "" || was == container || (container != "" && was < container)) {
			return false
		}
		set[key] = container
		return true
	}
	for id := range keys {
		add(id, id, "")
	}

	// A fixpoint over the function's own edges. Bounded by the number of (value, key)
	// pairs, which is what makes the loop terminate rather than a hop limit.
	for changed := true; changed; {
		changed = false
		for _, f := range fn.Flows {
			// A property READ off a value does not inherit what the value carries: a
			// field of a record fetched by one key is not that key.
			if f.Kind == "property" {
				continue
			}
			for k, container := range carries[f.From] {
				next := container
				if f.Kind == "enclose" && container == "" {
					next = f.To
				}
				if add(f.To, k, next) {
					changed = true
				}
			}
		}
		for _, c := range fn.Calls {
			if c.ResultID == "" {
				continue
			}
			for _, a := range c.Args {
				for k, container := range carries[a.ValueID] {
					if add(c.ResultID, k, container) {
						changed = true
					}
				}
			}
			for k, container := range carries[c.ReceiverID] {
				if add(c.ResultID, k, container) {
					changed = true
				}
			}
		}
	}
	return carries
}

func carriesIdentity(c *ir.Call, identity taint.Classified) bool {
	if c.ReceiverID != "" && identity.Values[c.ReceiverID] {
		return true
	}
	for _, a := range c.Args {
		if a.ValueID != "" && identity.Values[a.ValueID] {
			return true
		}
	}
	return false
}

// carriedKey is one key an operation was handed, and where in the call it sits.
type carriedKey struct {
	id string
	// container is the value the key was first enclosed into on its way to the call, or
	// empty when it arrived as an argument of its own. `{where: {id}, data: {teamId}}`
	// puts the two identifiers in different containers, which is the difference between
	// choosing the row and setting a field on it.
	container string
}

// unscoped returns the keys this operation carries that no check asked about, in a
// stable order.
func unscoped(op *ir.Call, carries map[string]map[string]string, scope map[string]bool) []carriedKey {
	seen := map[string]bool{}
	var out []carriedKey
	for _, a := range op.Args {
		for k, container := range carries[a.ValueID] {
			if scope[k] || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, carriedKey{id: k, container: container})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// related reports whether the handler tied the unauthorized key to the authorized one.
//
// Two shapes count, and one deliberately does not.
//
//   - A call carrying BOTH keys. `validateFeatureBelongsToProject({featureName,
//     projectId})` is a lookup of one key's owner against the other, and it is how the
//     sibling method of unleash's variant patch establishes exactly this relation.
//   - A comparison between them, in a branch the handler can leave from.
//
// A call carrying only the unauthorized key does not. `featureExists(name)` proves the
// row is there; existence is not ownership, and a check that establishes it relates the
// key to nothing at all.
//
// Both shapes must happen BEFORE the operation. A call after it cannot have gated it, and
// without that requirement the response itself qualifies: `json(result)` is handed what
// the write returned, and what the write returned was computed from both keys.
func related(g *cfg.Graph, fn *ir.Function, carries map[string]map[string]string, key string,
	scope map[string]bool, gates []*ir.Call, op *ir.Call, rule model.ScopeRule,
	keys map[string]requestKey) bool {

	isGate := make(map[string]bool, len(gates))
	for _, gate := range gates {
		isGate[gate.ID] = true
	}

	// A scope the CALLER chose cannot be extended to a second key by a lookup. Being
	// told which project to check the caller against is a parameter, not an
	// authorization, and a lookup that ties another key to it inherits that weakness
	// rather than curing it.
	if !chosenScope(scope, keys, rule) {
		for _, c := range fn.Calls {
			if isGate[c.ID] || c.ID == op.ID || !precedes(g, fn, c, op) {
				continue
			}
			var hasKey, hasScope bool
			for _, a := range c.Args {
				if _, ok := carries[a.ValueID][key]; ok {
					hasKey = true
				}
				for k := range scope {
					if _, ok := carries[a.ValueID][k]; ok {
						hasScope = true
					}
				}
			}
			if hasKey && hasScope {
				return true
			}
		}
	}

	for _, cmp := range fn.Comparisons {
		if cmp.Block == "" || !g.Dominates(cmp.Block, op.Block) {
			continue
		}
		var hasKey, hasScope bool
		for _, s := range []string{cmp.Left, cmp.Right} {
			if _, ok := carries[s][key]; ok {
				hasKey = true
			}
			for k := range scope {
				if _, ok := carries[s][k]; ok {
					hasScope = true
				}
			}
		}
		if hasKey && hasScope && g.IsGuard(cmp.Block) {
			return true
		}
	}
	return false
}

// precedes reports whether one call is unavoidably reached before another. Within a
// single block that is the order they were lowered in; across blocks it is dominance.
func precedes(g *cfg.Graph, fn *ir.Function, a, b *ir.Call) bool {
	if a.Block != b.Block {
		return g.Dominates(a.Block, b.Block)
	}
	for _, c := range fn.Calls {
		if c.ID == a.ID {
			return true
		}
		if c.ID == b.ID {
			return false
		}
	}
	return false
}

// chosenScope reports whether every key the gate was scoped to came from a container the
// caller filled in.
func chosenScope(scope map[string]bool, keys map[string]requestKey, rule model.ScopeRule) bool {
	if len(scope) == 0 {
		return false
	}
	for k := range scope {
		if !contains(rule.ChosenContainers, keys[k].container) {
			return false
		}
	}
	return true
}

// mutates reports whether this call writes to a store, by the verb it leads with. A read
// performed outside the authorized scope is worth knowing and is not what this reports:
// the operations named here are the ones that change something.
func mutates(c *ir.Call, rule model.ScopeRule) bool {
	name := c.Method
	if name == "" {
		name = lastSegment(c.Callee.Symbol)
	}
	if name == "" {
		name = c.Callee.Name
	}
	words := splitWords(name)
	if len(words) == 0 {
		return false
	}
	return contains(rule.Mutations, words[0])
}

func finding(ix *ir.Index, fn *ir.Function, ep *ir.EntryPoint, rule model.ScopeRule,
	keys map[string]requestKey, key carriedKey, scope map[string]bool, gate, op *ir.Call,
	reparents bool) taint.Finding {

	var scoped []string
	for k := range scope {
		scoped = append(scoped, keys[k].name)
	}
	sort.Strings(scoped)
	written := keys[key.id]

	chosen := ""
	if chosenScope(scope, keys, rule) {
		chosen = ", and the key it was checked against was chosen by the caller too"
	}
	// Two readings of the same relation, and which one applies is decided by whether the
	// authorized key is at the call at all. When it is, the row being written is the one
	// that was checked and this identifier is a field being set on it.
	reached := "%s.%s is a different record, and the caller chose it"
	if reparents {
		reached = "%s.%s is written into the record it checked, and names a different one the caller chose"
	}

	return taint.Finding{
		Analysis:      rule.ID,
		DataClass:     rule.IdentityClass,
		ChannelID:     rule.ID,
		Class:         rule.Finding,
		CWE:           rule.CWE,
		Message:       rule.Reason + chosen,
		Confidence:    taint.Medium,
		SourceLoc:     written.loc,
		SourceLabel:   written.container + "." + written.name,
		EntryPoint:    describeEntry(ep),
		EntryMethod:   ep.Detail["method"],
		EntryPath:     ep.Detail["path"],
		EntryAnchored: true,
		EntryTrust:    ep.TrustLevel(),
		InTestModule:  ix.InTestModule(op.Loc),
		SinkLoc:       op.Loc,
		SinkFunction:  fn.Name,
		SinkSymbol:    sinkName(op),
		SinkArgIndex:  -1,
		SinkContext:   "record-selector",
		SinkRational:  rule.Rationale,
		Path: []taint.Hop{
			{
				Loc: gate.Loc,
				Description: fmt.Sprintf("%s() is the check, and it asks about %s",
					calleeName(gate), strings.Join(scoped, ", ")),
				Resolution: gate.Callee.Resolution,
			},
			{
				Loc:         written.loc,
				Description: fmt.Sprintf(reached, written.container, written.name),
				Resolution:  ir.Resolved,
			},
			{
				Loc:         op.Loc,
				Description: fmt.Sprintf("%s() writes with it, and nothing relates the two", calleeName(op)),
				Resolution:  op.Callee.Resolution,
			},
		},
	}
}

func calleeName(c *ir.Call) string {
	if c.Method != "" {
		return c.Method
	}
	if c.Callee.Name != "" {
		return c.Callee.Name
	}
	return lastSegment(c.Callee.Symbol)
}

func sinkName(c *ir.Call) string {
	if c.Callee.Symbol != "" {
		return c.Callee.Symbol
	}
	return calleeName(c)
}

func describeEntry(ep *ir.EntryPoint) string {
	parts := make([]string, 0, 3)
	if m := ep.Detail["method"]; m != "" {
		parts = append(parts, m)
	}
	if p := ep.Detail["path"]; p != "" {
		parts = append(parts, p)
	}
	desc := strings.Join(parts, " ")
	// An entry point that is not a route has no method and no path, and its KIND alone
	// makes every one of them read the same. Whichever detail names this particular
	// registration -- the command an operator types, the event a bus delivers, the
	// schedule a timer keeps, the module a process starts in -- is what a reader needs
	// to find it, and it is the only thing distinguishing seventeen sibling jobs.
	if desc == "" {
		for _, key := range []string{"command", "event", "schedule", "trigger", "start"} {
			if v := ep.Detail[key]; v != "" {
				desc = ep.Kind + " " + v
				break
			}
		}
	}
	if desc == "" {
		desc = ep.Kind
	}
	if ep.Framework != "" {
		desc += " [" + ep.Framework + "]"
	}
	return desc
}

func leafOf(v *ir.Value) string {
	name := v.Path
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		name = v.Name
	}
	return name
}

// keyWord reports whether a field name ends in a word that names an identifier.
func keyWord(name string, words []string) bool {
	parts := splitWords(name)
	if len(parts) == 0 {
		return false
	}
	return contains(words, parts[len(parts)-1])
}

// splitWords breaks a name on camel-case boundaries and separators, lowercased.
// `projectId`, `project_id` and `PROJECT_ID` are one name spelled three ways.
func splitWords(name string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, strings.ToLower(cur.String()))
			cur.Reset()
		}
	}
	runes := []rune(name)
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ' ':
			flush()
		case r >= 'A' && r <= 'Z':
			// A run of capitals is one word: `ID` and `UUID` are not two.
			if i > 0 && !(runes[i-1] >= 'A' && runes[i-1] <= 'Z') {
				flush()
			}
			cur.WriteRune(r)
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

func lastSegment(symbol string) string {
	if i := strings.LastIndex(symbol, "."); i >= 0 {
		return symbol[i+1:]
	}
	return symbol
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func sortFindings(f []taint.Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].SinkLoc.File != f[j].SinkLoc.File {
			return f[i].SinkLoc.File < f[j].SinkLoc.File
		}
		if f[i].SinkLoc.Line != f[j].SinkLoc.Line {
			return f[i].SinkLoc.Line < f[j].SinkLoc.Line
		}
		return f[i].SourceLabel < f[j].SourceLabel
	})
}
