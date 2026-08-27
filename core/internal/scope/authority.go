package scope

// The second relation this analysis can state, and the operand it adds is the one the
// key relation has no way to name.
//
// The rule beside this one relates two REQUEST keys: the check asked about `projectId`,
// the write went to `strategyId`, and nothing tied them. It needs the caller's scope to
// have arrived in the request, because a request field is the only thing it can compare a
// request field against. A very common shape puts the scope somewhere else entirely --
// the authentication layer established it, the handler holds it inside a context object,
// and the question the handler asks is `may I act here` rather than `may I act on THIS`:
//
//	if (!ctx.repo.isSuperAdmin() && !ctx.repo.isProjectAdmin())
//	    return [forbidden];
//	const systemRepo = ctx.systemRepo;
//	await systemRepo.withTransaction(async (txRepo) => {
//	    let app = await txRepo.readResource('ClientApplication', req.params.id);
//	    app = await txRepo.updateResource({ ...app, secret: generateSecret(32) });
//
// There is still a relation between two calls here, and it is still a comparison of what
// they carry -- but what they carry is an ACCESSOR rather than a key. `ctx.repo` answered
// the permission question; `ctx.systemRepo` performed the operation. They are two
// accessors of one context, so whatever the first one's answer was scoped to, the second
// one does not carry it, and the record it reached was named by the caller.
//
// Three things keep this from being a rule about method names.
//
//   - The two accessors must hang off the SAME value. A check on one object and an
//     operation on an unrelated one is every program ever written; a check on one
//     accessor of a context and an operation through its sibling is a swap.
//   - The check must have been handed no request key, which is exactly the case the key
//     relation declines. The two rules partition rather than overlap.
//   - The operation must be keyed by a request field with nothing relating that record to
//     the caller's context -- the same exemptions the key relation grants, read against
//     the context instead of against a key.
//
// Nothing here knows which of the two accessors is the privileged one, and nothing needs
// to. The defect is the swap: a handler that asks and acts through the same accessor is
// silent whichever one it chose.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// accessor is a property read off a value the handler holds: which value it came from,
// and what it was called there. `ctx.repo` and `ctx.systemRepo` are two accessors of one
// context, and telling them apart is the whole judgement.
type accessor struct{ base, path string }

// frame is one function of the handler's BODY: the entry point's own function, or a
// callback the handler handed to one of its own calls.
//
// A callback written inline is part of the handler in every way that matters here. The
// gate above it has already run -- the handler returned before the closure was ever
// constructed -- and the frontend lowers a captured variable as a reference straight back
// into the enclosing function's values, so `req.params.id` read inside the callback is
// the same value the handler's own parameter produced. Refusing to look would have meant
// declining every handler that does its work inside a transaction.
//
// What is deliberately NOT followed is a call to a named function. Deciding which
// caller's gate governs which callee's write is the judgement `judge` refuses to make for
// the key relation, and this rule refuses it for the same reason.
type frame struct {
	fn    *ir.Function
	g     *cfg.Graph
	depth int
	// site is the call this frame was passed to, and host the frame holding that call.
	// Both are nil for the entry point's own function.
	site *ir.Call
	host *frame
}

// Bounds, not thresholds. A handler nests a callback inside a callback often enough to be
// worth two levels; past that the shape is a pipeline rather than a handler, and the cost
// is paid on every entry point of every program.
const (
	maxFrames = 24
	maxDepth  = 3
)

// flatten returns the handler's own function and the callbacks it passes, breadth first.
func flatten(ix *ir.Index, entry *ir.Function) []*frame {
	g := cfg.Build(entry)
	if g == nil {
		return nil
	}
	out := []*frame{{fn: entry, g: g}}
	seen := map[string]bool{entry.ID: true}
	for i := 0; i < len(out) && len(out) < maxFrames; i++ {
		host := out[i]
		if host.depth >= maxDepth {
			continue
		}
		for _, c := range host.fn.Calls {
			for _, a := range c.Args {
				if a.FunctionID == "" || seen[a.FunctionID] || len(out) >= maxFrames {
					continue
				}
				fn := ix.FuncByID[a.FunctionID]
				if fn == nil {
					continue
				}
				sub := cfg.Build(fn)
				if sub == nil {
					continue
				}
				seen[a.FunctionID] = true
				out = append(out, &frame{fn: fn, g: sub, depth: host.depth + 1, site: c, host: host})
			}
		}
	}
	return out
}

// judgeAuthority runs the accessor relation over one handler.
func judgeAuthority(ix *ir.Index, entry *ir.Function, ep *ir.EntryPoint, rule model.ScopeRule) []taint.Finding {
	frames := flatten(ix, entry)
	if len(frames) == 0 {
		return nil
	}
	values, keys := authorityKeys(frames, rule, ep.Detail["path"])
	if len(keys) == 0 {
		return nil
	}
	var flows []ir.Flow
	var calls []*ir.Call
	for _, f := range frames {
		flows = append(flows, f.fn.Flows...)
		calls = append(calls, f.fn.Calls...)
	}
	carries := propagate(flows, calls, keys)
	acc := accessorsOf(frames)

	// Every check the handler makes about one of its accessors, taken together. A
	// handler asking `isSuperAdmin()` and then `isProjectAdmin()` about the same object
	// has asked one question twice.
	var gates []placed
	for _, f := range frames {
		for _, c := range f.fn.Calls {
			if !authorizes(c, rule) || !f.g.IsGuard(c.Block) || len(acc[c.ReceiverID]) == 0 {
				continue
			}
			// A check handed a request key belongs to the key relation, which can say
			// something sharper about it. Leaving it there is what keeps the two rules
			// from reporting one handler twice.
			if handedKey(c, carries) {
				continue
			}
			gates = append(gates, placed{c, f})
		}
	}
	if len(gates) == 0 {
		return nil
	}

	// One finding per key. A handler that reads and then writes under the same
	// unauthorized identifier has made one mistake.
	reported := map[string]bool{}
	var out []taint.Finding
	for _, f := range frames {
		for _, op := range f.fn.Calls {
			if !selects(op, rule) {
				continue
			}
			used := authorityOf(op, f, acc)
			if len(used) == 0 {
				continue
			}
			for _, gate := range gates {
				asked := acc[gate.c.ReceiverID]
				base, ok := swapped(asked, used)
				if !ok || !before(gate.c, gate.f, op, f) {
					continue
				}
				if contextRelated(op, acc, used, base) {
					continue
				}
				k, ok := firstUnrelated(frames, carries, acc, used, base, gate, op, f, reported)
				if !ok {
					continue
				}
				reported[k.id] = true
				out = append(out, authorityFinding(ix, f.fn, ep, rule, values, keys, k,
					asked, used, gate.c, op))
				break
			}
		}
	}
	return out
}

// placed is a call together with the frame of the handler's body it sits in.
type placed struct {
	c *ir.Call
	f *frame
}

// firstUnrelated returns the first request key this operation carries that nothing tied
// to the caller's context.
func firstUnrelated(frames []*frame, carries map[string]map[string]string,
	acc map[string]map[accessor]bool, used map[accessor]bool, base string, gate placed,
	op *ir.Call, f *frame, reported map[string]bool) (carriedKey, bool) {

	for _, k := range unscoped(op, carries, nil) {
		if reported[k.id] {
			continue
		}
		if lookupRelated(frames, carries, acc, used, base, k.id, gate, op, f) {
			continue
		}
		return k, true
	}
	return carriedKey{}, false
}

// authorityKeys finds the request fields that name a record, over the whole body.
//
// The request is the ENTRY POINT's parameter and nothing else. A callback's own
// parameters are not the request -- `items.map(item => ...)` binds `item` to a row the
// program already had -- and treating them as one would make `item.id` a key the caller
// chose.
func authorityKeys(frames []*frame, rule model.ScopeRule, path string) (map[string]*ir.Value, map[string]requestKey) {
	values := map[string]*ir.Value{}
	for _, f := range frames {
		for i := range f.fn.Values {
			values[f.fn.Values[i].ID] = f.fn.Values[i]
		}
	}
	entry := frames[0].fn
	params := map[string]bool{}
	for i := range entry.Values {
		if v := entry.Values[i]; v.Kind == ir.ValueParam {
			params[v.ID] = true
		}
	}
	parsed := map[string]bool{}
	for _, c := range entry.Calls {
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
	for _, v := range values {
		if v.Kind != ir.ValueProperty || v.Base == "" || !keyWord(leafOf(v), rule.KeyWords) {
			continue
		}
		container, ok := containerOf(values, params, parsed, v)
		if !ok {
			continue
		}
		out[v.ID] = requestKey{id: v.ID, name: leafOf(v), container: container, loc: v.Loc}
	}
	// The handler's own PARAMETER, when the route named it. This is the whole of the
	// question in Python and it never arises in JavaScript: `/clients/<client_id>` binds
	// the segment to an argument, so `client_id` is a value the caller chose exactly as
	// `req.params.id` is, and a rule that only knows property reads is silent on every
	// Flask and Django handler ever written.
	//
	// Anchored to the ROUTE PATH rather than to the parameter's spelling. A parameter
	// whose name merely ends in `id` may be anything the framework injects, and the
	// engine already carries the registered path -- a name the path itself interpolates
	// came from the request and nothing else did.
	for _, p := range entry.Params {
		if p.ValueID == "" || !keyWord(p.Name, rule.KeyWords) || !pathNames(path, p.Name) {
			continue
		}
		v := values[p.ValueID]
		if v == nil {
			continue
		}
		out[p.ValueID] = requestKey{id: p.ValueID, name: p.Name, container: "route", loc: v.Loc}
	}
	return values, out
}

// pathNames reports whether a registered route path interpolates this name. Bare string
// containment on purpose: `/clients/<client_id>`, `/clients/:client_id` and
// `/clients/{client_id}` are three frameworks spelling one thing, and the engine's own
// path normalisation is not guaranteed to have kept any of them.
func pathNames(path, param string) bool {
	return param != "" && strings.Contains(path, param)
}

// accessorsOf carries accessor membership forward through the body's own assignments.
//
// A property read SEEDS an accessor and does not inherit one: `ctx` is not `ctx.repo`,
// and a rule that let a context carry every accessor hanging off it would find the two
// sides of every swap equal. Everything else propagates, because `const systemRepo =
// ctx.systemRepo` is the same accessor under a shorter name.
//
// Call results deliberately do not propagate. What a call returns is a new thing, not the
// accessor it was made on, and inheriting there would make every result of `ctx.repo.f()`
// an alias for `ctx.repo`.
func accessorsOf(frames []*frame) map[string]map[accessor]bool {
	out := map[string]map[accessor]bool{}
	add := func(id string, a accessor) bool {
		if id == "" {
			return false
		}
		set, ok := out[id]
		if !ok {
			set = map[accessor]bool{}
			out[id] = set
		}
		if set[a] {
			return false
		}
		set[a] = true
		return true
	}
	for _, f := range frames {
		for _, v := range f.fn.Values {
			if v.Kind == ir.ValueProperty && v.Base != "" {
				add(v.ID, accessor{base: v.Base, path: leafOf(v)})
			}
		}
	}
	// A fixpoint over the body's own edges, bounded by the number of (value, accessor)
	// pairs rather than by a hop limit.
	for changed := true; changed; {
		changed = false
		for _, f := range frames {
			for _, fl := range f.fn.Flows {
				if fl.Kind == "property" {
					continue
				}
				for a := range out[fl.From] {
					if add(fl.To, a) {
						changed = true
					}
				}
			}
		}
	}
	return out
}

// authorityOf names the accessor an operation went through.
//
// Its own receiver when that says something, and otherwise the accessor the frame it sits
// in was entered by: `ctx.systemRepo.withTransaction(async (txRepo) => ...)` binds
// `txRepo` to the very repository the call was made on, and the callback never spells
// that out again. Whatever a body reached by a call on an accessor does, it does through
// that accessor.
func authorityOf(op *ir.Call, f *frame, acc map[string]map[accessor]bool) map[accessor]bool {
	if own := acc[op.ReceiverID]; len(own) > 0 {
		return own
	}
	for cur := f; cur != nil && cur.site != nil; cur = cur.host {
		if outer := acc[cur.site.ReceiverID]; len(outer) > 0 {
			return outer
		}
	}
	return nil
}

// swapped reports whether two accessor sets name different accessors of the SAME value,
// and returns that value.
//
// Sharing the base is what makes the comparison mean anything. Two accessors of one
// context are alternatives the handler chose between; two properties of unrelated objects
// are just two objects.
func swapped(asked, used map[accessor]bool) (string, bool) {
	for a := range asked {
		if used[a] {
			return "", false
		}
	}
	// The smallest shared base, so that a handler holding two contexts reports the same
	// one on every run rather than whichever the map happened to yield first.
	shared := ""
	for a := range asked {
		for b := range used {
			if a.base == b.base && (shared == "" || a.base < shared) {
				shared = a.base
			}
		}
	}
	return shared, shared != ""
}

// contextRelated reports whether the operation was ALSO handed something out of the
// context whose accessor answered the check.
//
// `updateResource(id, { project: ctx.project })` cannot reach another project's row: the
// constraint is in the selection rather than in a check above it, which is how this kind
// of code is normally written. The operation's own accessor does not count -- that is
// the thing being questioned, not a constraint on it.
func contextRelated(op *ir.Call, acc map[string]map[accessor]bool, used map[accessor]bool, base string) bool {
	for _, a := range op.Args {
		for x := range acc[a.ValueID] {
			if x.base == base && !used[x] {
				return true
			}
		}
	}
	return false
}

// lookupRelated reports whether the handler tied this record to the caller's context
// before operating on it.
//
// The same two shapes the key relation accepts, read against a context instead of a key:
// a call carrying both the record's key and something out of that context is a lookup of
// one against the other, and a comparison between them in a branch the handler can leave
// from is the check written out longhand. A call carrying only the key does not count --
// existence is not ownership.
func lookupRelated(frames []*frame, carries map[string]map[string]string,
	acc map[string]map[accessor]bool, used map[accessor]bool, base, key string,
	gate placed, op *ir.Call, f *frame) bool {

	// Some accessor of the context OTHER than the one being questioned. The operation's
	// own accessor cannot vouch for the operation: reading a row through the elevated
	// repository and then writing it through the elevated repository is the weakness
	// twice, not a constraint on it.
	other := func(id string) bool {
		for x := range acc[id] {
			if x.base == base && !used[x] {
				return true
			}
		}
		return false
	}

	for _, c := range frames {
		for _, call := range c.fn.Calls {
			if call.ID == gate.c.ID || call.ID == op.ID || !before(call, c, op, f) {
				continue
			}
			// The RECEIVER counts, and that is the shape that matters most here:
			// fetching the record through an accessor of the context is the ordinary fix
			// for the weakness this rule reports. medplum's handler becomes correct by
			// reading the client application through `ctx.repo` -- which cannot return
			// one the caller's project does not hold -- and only then writing it through
			// `ctx.systemRepo`, leaving the elevated repository doing what it is for.
			hasContext := other(call.ReceiverID)
			hasKey := false
			for _, a := range call.Args {
				if _, ok := carries[a.ValueID][key]; ok {
					hasKey = true
				}
				if other(a.ValueID) {
					hasContext = true
				}
			}
			if hasKey && hasContext {
				return true
			}
		}
	}

	for _, c := range frames {
		for _, cmp := range c.fn.Comparisons {
			if cmp.Block == "" || !c.g.IsGuard(cmp.Block) || !beforeBlock(cmp.Block, c, op, f) {
				continue
			}
			var hasKey, hasContext bool
			for _, s := range []string{cmp.Left, cmp.Right} {
				if _, ok := carries[s][key]; ok {
					hasKey = true
				}
				if other(s) {
					hasContext = true
				}
			}
			if hasKey && hasContext {
				return true
			}
		}
	}
	return false
}

// handedKey reports whether a call was given one of the request's own identifiers.
func handedKey(c *ir.Call, carries map[string]map[string]string) bool {
	for _, a := range c.Args {
		if len(carries[a.ValueID]) > 0 {
			return true
		}
	}
	return false
}

// selects reports whether this call operates on a record that already exists, by the verb
// it leads with. Read or write -- see ScopeRule.Selects for what that widening measured.
func selects(c *ir.Call, rule model.ScopeRule) bool {
	name := c.Method
	if name == "" {
		name = lastSegment(c.Callee.Symbol)
	}
	if name == "" {
		name = c.Callee.Name
	}
	words := splitWords(name)
	return len(words) > 0 && contains(rule.Selects, words[0])
}

// authorizes reports whether a call's name says it is an authorization question.
func authorizes(c *ir.Call, rule model.ScopeRule) bool {
	name := c.Method
	if name == "" {
		name = lastSegment(c.Callee.Symbol)
	}
	if name == "" {
		name = c.Callee.Name
	}
	for _, w := range splitWords(name) {
		if contains(rule.Authorizes, w) {
			return true
		}
	}
	return false
}

// before reports whether one call in the handler's body is unavoidably reached before
// another.
func before(a *ir.Call, af *frame, b *ir.Call, bf *frame) bool {
	blk, at, ok := lift(af, b, bf)
	if !ok {
		return false
	}
	if a.Block != blk {
		return af.g.Dominates(a.Block, blk)
	}
	// Same block, so the order they were lowered in is the order they run in.
	for _, c := range af.fn.Calls {
		if c.ID == a.ID {
			return true
		}
		if c.ID == at.ID {
			return false
		}
	}
	return false
}

// beforeBlock is the same question asked about a block rather than a call, for the
// comparisons a handler makes.
func beforeBlock(block string, af *frame, b *ir.Call, bf *frame) bool {
	blk, _, ok := lift(af, b, bf)
	return ok && af.g.Dominates(block, blk)
}

// lift walks a call up out of the callbacks it sits inside until it is a position in the
// given frame: the block the outermost enclosing call occupies, and that call.
//
// This is what makes control flow one graph again. A callback's own graph says nothing
// about what ran before the handler constructed it, and the position that answers that is
// the position of the call the callback was handed to.
func lift(af *frame, b *ir.Call, bf *frame) (string, *ir.Call, bool) {
	blk, at := b.Block, b
	for f := bf; f != nil; f = f.host {
		if f == af {
			return blk, at, true
		}
		if f.site == nil {
			return "", nil, false
		}
		blk, at = f.site.Block, f.site
	}
	return "", nil, false
}

func authorityFinding(ix *ir.Index, fn *ir.Function, ep *ir.EntryPoint, rule model.ScopeRule,
	values map[string]*ir.Value, keys map[string]requestKey, key carriedKey,
	asked, used map[accessor]bool, gate, op *ir.Call) taint.Finding {

	written := keys[key.id]
	// The label spells the property the way the source spells it. `req.params.id` and
	// `req.id` are one value to this analysis, and only one of them can be found by a
	// reader with a text editor.
	spelled := written.container + "." + written.name
	if v := values[key.id]; v != nil && v.Path != "" {
		spelled = written.container + "." + v.Path
	}
	askedName := name(values, asked)
	usedName := name(values, used)

	return taint.Finding{
		Analysis:      rule.ID,
		DataClass:     rule.IdentityClass,
		ChannelID:     rule.ID,
		Class:         rule.Finding,
		CWE:           rule.CWE,
		Message:       rule.Reason,
		Confidence:    taint.Medium,
		SourceLoc:     written.loc,
		SourceLabel:   spelled,
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
				Description: fmt.Sprintf("%s() is the check, and it asks %s",
					calleeName(gate), askedName),
				Resolution: gate.Callee.Resolution,
			},
			{
				Loc:         written.loc,
				Description: fmt.Sprintf("%s names the record, and the caller chose it", spelled),
				Resolution:  ir.Resolved,
			},
			{
				Loc: op.Loc,
				Description: fmt.Sprintf("%s() acts through %s, which nothing asked about",
					calleeName(op), usedName),
				Resolution: op.Callee.Resolution,
			},
		},
	}
}

// name spells an accessor set the way the handler wrote it, so a reader can find it.
func name(values map[string]*ir.Value, set map[accessor]bool) string {
	var out []string
	for a := range set {
		spelled := a.path
		if base := values[a.base]; base != nil && base.Name != "" {
			spelled = base.Name + "." + a.path
		}
		out = append(out, spelled)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return "an accessor this analysis could not name"
	}
	return joinWords(out)
}

func joinWords(parts []string) string {
	switch len(parts) {
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	default:
		out := ""
		for i, p := range parts {
			switch {
			case i == 0:
				out = p
			case i == len(parts)-1:
				out += " and " + p
			default:
				out += ", " + p
			}
		}
		return out
	}
}
