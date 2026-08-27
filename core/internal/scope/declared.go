package scope

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// judgeDeclared states the package's relation over a view whose two operands are
// declarations rather than calls.
//
// Nothing here is a second analysis. The question is the one the file above asks -- which
// record was the authorization about, and which record does the operation touch -- and
// the only difference is that a declaratively registered view answers it in class
// attributes instead of in a control-flow graph. The framework reads `permission_classes`
// to decide who may proceed and `lookup_url_kwarg` to decide which row to fetch, and if
// those two name different request keys with nothing between them, the caller is
// authorized for one record and served another.
//
// What the view is silent about is what makes it a finding. A correctly written DRF view
// says the relation out loud in one of two places: it narrows `get_queryset()` by the
// authorized key, or it declares an object-level permission and lets the framework hand
// the selected row to it. Both are read here, and either one ends the judgement about the
// framework's own selection.
//
// The methods the view DOES write are judged too, under the same declared gate, and
// neither of those exemptions applies to them -- see judgeBody.
func judgeDeclared(ix *ir.Index, d *ir.IR, rule model.ScopeRule,
	identity taint.Classified) []taint.Finding {
	var out []taint.Finding
	// One finding per DECLARATION, not per class. Six of doccano's label views inherit
	// one `get_queryset` from one base, and reporting the same line six times under six
	// class names tells a reader nothing the first line did not.
	reported := map[string]bool{}

	views := make([]ir.DeclaredView, len(d.DeclaredViews))
	copy(views, d.DeclaredViews)
	sort.Slice(views, func(i, j int) bool { return views[i].ID < views[j].ID })

	for i := range views {
		v := &views[i]
		// A view whose declared authorization consults no request key at all is not
		// scoped to a record: `IsAuthenticated` says something true about the caller and
		// nothing about which row is being touched. There is no scope here to compare a
		// selection against, and 52 of wger's declared views are that shape -- which is
		// most of why this rule is quiet on code that is correct.
		if !contains(rule.Declared.Frameworks, v.Framework) || len(v.Authorizes) == 0 {
			continue
		}
		authorized := map[string]bool{}
		for _, a := range v.Authorizes {
			authorized[a.Key] = true
		}

		// The body is judged FIRST and under neither exemption, because neither one is
		// about it. A `get_queryset()` narrowed to the authorized project constrains what
		// the framework fetches and constrains nothing at all in a `delete()` that never
		// calls it -- which is the difference doccano's label-type bulk delete IS: the
		// list query beside it is project-scoped and the delete takes primary keys
		// straight out of the body. `has_object_permission` is the same story one hook
		// along: DRF calls it from `get_object()`, and a method that fetches its own rows
		// never reaches it.
		for _, f := range judgeBody(ix, v, rule, authorized, identity) {
			at := f.SourceLoc.String() + "|" + f.SinkLoc.String()
			if reported[at] {
				continue
			}
			reported[at] = true
			out = append(out, f)
		}

		// The framework's own hook for relating the selected row to the requester. An
		// application that declared one has answered this question in the place provided
		// for answering it, and the URL keys say nothing about it either way.
		if v.ObjectRelation != "" || relatedByQuery(v, authorized) {
			continue
		}
		key, sink := unrelatedKey(v, authorized)
		if key == nil {
			continue
		}
		at := key.Loc.String() + "|" + key.Key
		if reported[at] {
			continue
		}
		reported[at] = true
		out = append(out, declaredFinding(ix, rule, v, key, sink, authorized))
	}
	return out
}

// judgeBody runs the same relation over the code the framework dispatches INTO.
//
// A declaratively authorized view is not always empty. It routinely carries one method
// the framework has no opinion about -- a bulk `delete()` taking a list of primary keys
// out of the request body -- and that method runs under an authorization it never
// mentions, because the class declared it. The CFG rule beside this one cannot judge it:
// it looks for a gate CALL inside the body, finds none, and stops before it reaches the
// write.
//
// The gate needs no dominance test here. A permission class runs before dispatch, so
// whatever it was scoped to governs every path in every method of the class -- which is
// the one thing this shape makes EASIER rather than harder.
func judgeBody(ix *ir.Index, v *ir.DeclaredView, rule model.ScopeRule,
	authorized map[string]bool, identity taint.Classified) []taint.Finding {

	if len(v.Handlers) == 0 || len(rule.Mutations) == 0 {
		return nil
	}
	var out []taint.Finding
	for _, id := range v.Handlers {
		fn := ix.FuncByID[id]
		if fn == nil {
			continue
		}
		out = append(out, judgeHandler(ix, fn, v, rule, authorized, identity)...)
	}
	return out
}

func judgeHandler(ix *ir.Index, fn *ir.Function, v *ir.DeclaredView, rule model.ScopeRule,
	authorized map[string]bool, identity taint.Classified) []taint.Finding {

	keys := requestKeys(fn, rule)
	if len(keys) == 0 {
		return nil
	}
	// Three more things a value can have come from, all of them relations this judgement
	// must see and none of them a field of the request.
	//
	// The view's own accessors: `self.project.examples` is a query already narrowed to
	// the authorized project, and the body says so nowhere.
	//
	// The caller's identity: `Comment.objects.filter(user=request.user, pk__in=ids)`
	// cannot reach a row the requester does not own, which relates it to the requester
	// directly rather than to the key the permission named.
	//
	// Only an accessor that resolves to an AUTHORIZED key is seeded. The purpose here is
	// to see a relation the body does not spell out; seeding the others would mean
	// reporting the same missing relation twice, once at the declaration and once at
	// every line that reads it.
	related := map[string]bool{}
	values := make(map[string]*ir.Value, len(fn.Values))
	for i := range fn.Values {
		values[fn.Values[i].ID] = fn.Values[i]
	}
	for i := range fn.Values {
		val := fn.Values[i]
		if val.Kind == ir.ValueProperty && val.Base != "" {
			if key, ok := resolverOf(values, v, val); ok && authorized[key] {
				keys[val.ID] = requestKey{id: val.ID, name: key, container: "kwargs", loc: val.Loc}
				related[val.ID] = true
			}
		}
		if identity.Values[val.ID] {
			keys[val.ID] = requestKey{id: val.ID, name: "", container: "actor", loc: val.Loc}
			related[val.ID] = true
		}
	}
	// The same accessor written as a call. `self.get_queryset()` returns rows the class
	// already narrowed, and an application that calls it has used the relation it wrote.
	for _, c := range fn.Calls {
		if c.ResultID == "" || c.Method == "" {
			continue
		}
		base := values[c.ReceiverID]
		if base == nil || base.Kind != ir.ValueParam || base.Name != "self" {
			continue
		}
		if key, ok := resolverNamed(v, c.Method); ok && authorized[key] {
			keys[c.ResultID] = requestKey{id: c.ResultID, name: key, container: "kwargs", loc: c.Loc}
			related[c.ResultID] = true
		}
	}
	carries := propagate(fn.Flows, fn.Calls, keys)

	var out []taint.Finding
	reported := map[string]bool{}
	for _, op := range fn.Calls {
		if !mutates(op, rule) {
			continue
		}
		carried := operandKeys(op, carries)
		if scopedBy(carried, keys, related, authorized) {
			continue
		}
		for _, id := range sortedKeys(carried) {
			name := keys[id].name
			if name == "" || authorized[name] || reported[name] {
				continue
			}
			reported[name] = true
			out = append(out, bodyFinding(ix, rule, v, fn, keys[id], op, authorized))
			break
		}
	}
	return out
}

// resolverOf reports which request key a `self.<accessor>` read stands for.
//
// The FIRST segment of the path is what names the accessor: `self.project.examples` reads
// a field of the row `project` resolved, and a field of a row inside the authorized scope
// is inside it too.
func resolverOf(values map[string]*ir.Value, v *ir.DeclaredView, val *ir.Value) (string, bool) {
	base := values[val.Base]
	if base == nil || base.Kind != ir.ValueParam || base.Name != "self" {
		return "", false
	}
	head := val.Path
	if i := strings.IndexByte(head, '.'); i >= 0 {
		head = head[:i]
	}
	return resolverNamed(v, head)
}

func resolverNamed(v *ir.DeclaredView, name string) (string, bool) {
	for _, r := range v.Resolves {
		if r.By == name {
			return r.Key, true
		}
	}
	return "", false
}

// operandKeys returns every request key an operation was handed, the RECEIVER included.
//
// The receiver is where a Django write keeps its selection: `Model.objects.filter(pk__in=
// ids).delete()` hands `delete()` no argument at all, and everything deciding which rows
// vanish is on the left of the dot. Reading only the arguments finds no key on any bulk
// delete an ORM ever wrote.
func operandKeys(op *ir.Call, carries map[string]map[string]string) map[string]bool {
	out := map[string]bool{}
	for _, a := range op.Args {
		for k := range carries[a.ValueID] {
			out[k] = true
		}
	}
	for k := range carries[op.ReceiverID] {
		out[k] = true
	}
	return out
}

// scopedBy reports whether the operation also carries something that relates it to what
// was authorized -- a key the check was about, an accessor that resolves to one, or the
// caller's own identity. Either way the rows it can reach are already inside the scope.
//
// Position is deliberately not read, where the rule beside this one reads it closely. It
// separates a key that SELECTS the row from one written INTO it, and that distinction
// needs the operation's own argument shape: a Django write puts its whole selection on the
// receiver, so there is no position left to compare. The cost is a re-parenting write
// under a declared gate, which is stated rather than claimed.
func scopedBy(carried map[string]bool, keys map[string]requestKey, related, authorized map[string]bool) bool {
	for id := range carried {
		if related[id] || authorized[keys[id].name] {
			return true
		}
	}
	return false
}

func bodyFinding(ix *ir.Index, rule model.ScopeRule, v *ir.DeclaredView, fn *ir.Function,
	key requestKey, op *ir.Call, authorized map[string]bool) taint.Finding {

	f := declaredBase(ix, rule, v, authorized, key.loc, op.Loc)
	f.Message = rule.Declared.BodyReason
	f.SourceLabel = key.container + "." + key.name
	f.SinkFunction = fn.Name
	f.SinkSymbol = sinkName(op)
	f.SinkRational = rule.Declared.BodyRationale
	f.Path[1].Description = fmt.Sprintf("%s.%s is a different record, and the caller chose it",
		key.container, key.name)
	f.Path[2].Description = fmt.Sprintf("%s() writes with it under a check that never named it",
		calleeName(op))
	f.Path[2].Resolution = op.Callee.Resolution
	return f
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// relatedByQuery reports whether the application's own query override narrows the view to
// a key the authorization was about.
//
// This is the relation, and it is the one a correct view actually writes:
// `Tag.objects.filter(project=self.kwargs["project_id"])` says the framework may not
// reach outside the project the permission class checked. Nothing weaker counts -- a
// narrowing by some OTHER caller-chosen key relates the row to a second thing the caller
// picked, which is the weakness rather than the fix.
func relatedByQuery(v *ir.DeclaredView, authorized map[string]bool) bool {
	for _, c := range v.Constrains {
		if authorized[c.Key] {
			return true
		}
	}
	return false
}

// unrelatedKey returns the request key the operation is resolved from when no check asked
// about it, and the line to report the operation at.
//
// Two shapes, in the order they decide the record. A declared lookup key IS the selection:
// the framework fetches by it and serves the row to every verb the class answers. Where
// the class declares no lookup it answers about a collection, and then the narrowing in
// its own `get_queryset()` is the selection -- a list of annotations narrowed to an
// example, under a permission that was about a project, reaches every project's
// annotations one example at a time.
func unrelatedKey(v *ir.DeclaredView, authorized map[string]bool) (*ir.DeclaredKey, ir.Loc) {
	if v.Selects != nil {
		if authorized[v.Selects.Key] {
			return nil, ir.Loc{}
		}
		if v.Target != nil {
			return v.Selects, v.Target.Loc
		}
		return v.Selects, v.Selects.Loc
	}
	for i := range v.Constrains {
		if !authorized[v.Constrains[i].Key] {
			return &v.Constrains[i], v.Constrains[i].Loc
		}
	}
	return nil, ir.Loc{}
}

func declaredFinding(ix *ir.Index, rule model.ScopeRule, v *ir.DeclaredView,
	key *ir.DeclaredKey, sink ir.Loc, authorized map[string]bool) taint.Finding {

	symbol := v.Name + "." + key.By
	if v.Target != nil && v.Target.Symbol != "" {
		symbol = v.Target.Symbol
	}

	f := declaredBase(ix, rule, v, authorized, key.Loc, sink)
	f.Message = rule.Reason
	f.SourceLabel = "kwargs." + key.Key
	f.SinkFunction = v.Name
	f.SinkSymbol = symbol
	f.SinkRational = rule.Rationale
	f.Path[1].Description = fmt.Sprintf("%s names %s, which the caller chose and no check was about",
		key.By, key.Key)
	f.Path[2].Description = fmt.Sprintf(
		"%s is what the framework resolves with it, and %s declares nothing relating the two",
		symbol, v.Name)
	return f
}

// declaredBase holds everything the two halves of this rule agree on: the same weakness,
// the same declared gate, and the same three-hop story -- what the check was about, which
// key the operation used instead, and where that operation is.
func declaredBase(ix *ir.Index, rule model.ScopeRule, v *ir.DeclaredView,
	authorized map[string]bool, source, sink ir.Loc) taint.Finding {

	var scoped []string
	for k := range authorized {
		scoped = append(scoped, k)
	}
	sort.Strings(scoped)
	gate := v.Authorizes[0]

	return taint.Finding{
		Analysis:   rule.ID,
		DataClass:  "record-selector",
		ChannelID:  rule.ID,
		Class:      rule.Finding,
		CWE:        rule.CWE,
		Confidence: taint.Medium,

		SourceLoc: source,
		// The registration IS the surface enumeration here (ADR-009). The frontend
		// emitted this view because a URLconf or a router names it, and the reason there
		// is often no function to anchor to is the whole subject of the finding.
		EntryPoint:    "declared view " + v.Name + " [" + v.Framework + "]",
		EntryAnchored: true,
		EntryTrust:    ir.Remote,
		InTestModule:  ix.InTestModule(sink),

		SinkLoc:      sink,
		SinkArgIndex: -1,
		SinkContext:  "record-selector",

		Path: []taint.Hop{
			{
				Loc: gate.Loc,
				Description: fmt.Sprintf("%s is the declared check, and it asks about %s",
					gate.By, strings.Join(scoped, ", ")),
				Resolution: ir.Resolved,
			},
			{Loc: source, Resolution: ir.Resolved},
			{Loc: sink, Resolution: ir.Resolved},
		},
	}
}
