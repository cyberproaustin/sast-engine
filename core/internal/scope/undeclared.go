// judgeUndeclared states this package's relation where the gate operand is a declaration
// the operation did NOT make.
//
// `declared.go` reads two declarations and asks whether they name the same record.
// `scope.go` reads two calls and asks the same thing. Here the gate is empty: a graphene
// mutation states who may call it in `Meta.permissions`, and `BaseMutation.check_permissions`
// returns True when there is nothing there --
//
//	all_permissions = permissions or cls._meta.permissions
//	if not all_permissions:
//	    return True
//
// -- so an operation that declared none is open to anybody who can reach the schema. That
// is a fact about a class, never a call, and no analysis in this engine could read it
// before the frontend enumerated the declaration as a control on the entry point.
//
// The relation is what makes it a finding, exactly as in the two rules beside it. An open
// operation that resolves a record from an identifier the CALLER wrote, and never brings
// that record and the requester together anywhere, has let the caller choose whose row it
// operates on. An open operation that does bring them together has authorized per-record
// instead of per-caller, which is a design and not a defect -- and it is what almost all
// of saleor's undeclared mutations do.
//
// # Why the absence is a condition and never the finding
//
// Because absence is the norm. 54 of saleor's 331 mutations declare no permission, and 16
// of the 20 modules under `graphql/checkout/mutations/` declare none -- a storefront API
// is supposed to be callable by a shopper. A rule that reported the anomaly would be wrong
// about sixteen siblings, and one with a conformance threshold would be silent about all
// of them. That was measured before this was written. What the declaration is good for is
// what it does here: it says which operations have no per-caller gate at all, so the
// relation below is asked only where its failure means something.
package scope

import (
	"fmt"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

func judgeUndeclared(ix *ir.Index, d *ir.IR, rule model.ScopeRule,
	identity, input taint.Classified) []taint.Finding {

	shape := rule.Undeclared
	// The caller's identity has to be observable somewhere in the program, for the
	// reason the ownership policy states: a relation to the requester cannot be judged
	// where nothing in this engine's vocabulary names the requester, and reporting every
	// selection as unrelated would be a statement about the vocabulary (ADR-003).
	if len(identity.Values) == 0 || len(input.Values) == 0 {
		return nil
	}

	var out []taint.Finding
	reported := map[string]bool{}
	for i := range d.EntryPoints {
		ep := &d.EntryPoints[i]
		if !openOperation(ep, shape) {
			continue
		}
		fn := ix.FuncByID[ep.FunctionID]
		if fn == nil || ix.InTestModule(fn.Loc) {
			continue
		}
		for _, f := range judgeResolver(ix, fn, ep, rule, identity, input) {
			at := f.SinkLoc.String()
			if reported[at] {
				continue
			}
			reported[at] = true
			out = append(out, f)
		}
	}
	return out
}

// openOperation reports whether this entry point is one whose framework declares
// permissions and which declared none.
func openOperation(ep *ir.EntryPoint, shape *model.UndeclaredScope) bool {
	if !contains(shape.Frameworks, ep.Framework) || !contains(shape.EntryKinds, ep.Kind) {
		return false
	}
	if len(shape.Methods) > 0 && !contains(shape.Methods, ep.Detail["method"]) {
		return false
	}
	for _, m := range ep.Middleware {
		if m.Symbol == shape.Control {
			return false
		}
	}
	return true
}

func judgeResolver(ix *ir.Index, fn *ir.Function, ep *ir.EntryPoint, rule model.ScopeRule,
	identity, input taint.Classified) []taint.Finding {

	shape := rule.Undeclared
	var out []taint.Finding
	for _, sel := range fn.Calls {
		if !selectsRecord(ix, sel, shape.Selectors) {
			continue
		}
		named := namedArg(sel, input)
		if named == "" {
			continue
		}
		subject, known := subjectOf(fn, sel, shape)
		if !known || withinSubject(ep, subject) {
			// Either the operation resolves a record of its own subject -- where an
			// empty gate is the design and not the defect -- or the type was written in
			// a spelling this cannot resolve to a package, which is a refusal rather
			// than a foreign subject.
			continue
		}
		if len(requestSeeds(fn, identity, shape)) == 0 {
			// The mutation was handed no request it could ask a question with. Nothing
			// here is a claim that it should have -- 42 judgements on entry points with
			// no identity in reach were adjudicated at 0.00 precision, and this analysis
			// declines them the same way the ownership policy does.
			continue
		}
		record := recordReach(fn, recordSeeds(sel, named))
		if relatesRecord(ix, fn, sel, record, identity, shape, 0) {
			continue
		}
		out = append(out, undeclaredFinding(ix, fn, ep, rule, sel, named, subject))
	}
	return out
}

// selects reports whether this call turns an opaque identifier into a record.
//
// Matched on the leaf name, because the same call is written `cls.get_node_or_error(...)`
// on a class and `from_global_id(id)` as a free function, and a resolved local call
// carries no symbol at all -- the name is on the function it resolved to.
func selectsRecord(ix *ir.Index, c *ir.Call, names []string) bool {
	leaf := leafOfName(c.Callee.Symbol)
	if leaf == "" {
		leaf = c.Method
	}
	if leaf == "" {
		leaf = leafOfName(c.Callee.Name)
	}
	if leaf == "" {
		if fn := ix.FuncByID[c.Callee.FunctionID]; fn != nil {
			leaf = fn.Name
		}
	}
	for _, n := range names {
		if leaf == n {
			return true
		}
	}
	return false
}

// namedArg is the argument holding the identifier the CALLER wrote, or empty where the
// selector was handed something the program computed. A global id built by the server --
// `graphene.Node.to_global_id("Checkout", token)` for a token it just generated -- names
// no record the caller chose.
func namedArg(sel *ir.Call, input taint.Classified) string {
	for _, a := range sel.Args {
		if a.ValueID == "" || !input.Values[a.ValueID] {
			continue
		}
		// The record's own type, passed as `only_type=Order`, is not the identifier.
		if a.Name == "only_type" || a.Name == "field" || a.Name == "code" || a.Name == "qs" {
			continue
		}
		return a.ValueID
	}
	return ""
}

// subjectOf is the package the decoded record's TYPE is defined in, and whether the
// program said enough for that to be an answer.
//
// A frontend that resolved the import writes the type's own module into the value's name
// -- `saleor.graphql.order.types.Order` -- and a qualified spelling like
// `checkout_types.Checkout` lowers to a property with nothing but the leaf on it. The
// second is a refusal: nothing about how a name was written says which subject it belongs
// to, and a rule that read the spelling would judge the import style.
func subjectOf(fn *ir.Function, sel *ir.Call, shape *model.UndeclaredScope) (string, bool) {
	if shape.SubjectArg == "" {
		return "", false
	}
	var id string
	for _, a := range sel.Args {
		if a.Name == shape.SubjectArg {
			id = a.ValueID
			break
		}
	}
	if id == "" {
		return "", false
	}
	for _, v := range fn.Values {
		if v.ID != id {
			continue
		}
		if v.Kind != ir.ValueGlobal || !strings.Contains(v.Name, ".") {
			return "", false
		}
		// The package, which is the name without the class itself.
		return v.Name[:strings.LastIndexByte(v.Name, '.')], true
	}
	return "", false
}

// withinSubject reports whether the operation and the type it decodes belong to the same
// part of the application.
//
// Segment-wise, and the test is that they agree on everything but the last name each
// side. `saleor.graphql.checkout.types` against `saleor/graphql/checkout/mutations/...`
// agrees down to `saleor.graphql.checkout` and differs only in `types` against
// `mutations`, so the checkout mutation is operating on checkouts. The same module
// against `saleor.graphql.order.types` agrees only on `saleor.graphql`, which is the API
// and not a subject.
func withinSubject(ep *ir.EntryPoint, subject string) bool {
	module := ep.Detail["module"]
	if module == "" || subject == "" {
		// Nothing to compare against, and a rule with one operand states nothing.
		return true
	}
	module = strings.TrimSuffix(module, ".py")
	module = strings.ReplaceAll(strings.ReplaceAll(module, "/", "."), "\\", ".")
	want := strings.Split(subject, ".")
	if len(want) < 2 {
		return true
	}
	want = want[:len(want)-1]
	have := strings.Split(module, ".")
	if len(have) < len(want) {
		return false
	}
	for i, seg := range want {
		if have[i] != seg {
			return false
		}
	}
	return true
}

func recordSeeds(sel *ir.Call, named string) map[string]bool {
	seeds := map[string]bool{named: true}
	if sel.ResultID != "" {
		seeds[sel.ResultID] = true
	}
	return seeds
}

// requestSeeds is where the caller lives inside this resolver: the caller's identity as
// the model names it, and the request object the framework parameter carries.
//
// Both, because saleor writes its permission helpers both ways. `check_can_edit_address(
// info.context, address)` hands over the whole request and `fetch_shipping_methods_for_checkout(
// checkout_info, requestor=requestor)` hands over the resolved requester, and each is the
// same statement about the same two things.
func requestSeeds(fn *ir.Function, identity taint.Classified,
	shape *model.UndeclaredScope) map[string]bool {

	seeds := map[string]bool{}
	for _, v := range fn.Values {
		if identity.Values[v.ID] {
			seeds[v.ID] = true
		}
		if v.Kind == ir.ValueProperty && contains(shape.RequestPaths, leafOf(v)) {
			seeds[v.ID] = true
		}
	}
	return seeds
}

// reach is the seeds and everything the function computed out of them, following flows
// and property reads.
//
// `order.channel` is part of the order and `info.context.user` is part of the request:
// reading a field of a thing keeps you inside it. Iterated rather than ordered, because
// the values are a list and not a dependency graph.
func reach(fn *ir.Function, seeds map[string]bool, callResults bool) map[string]bool {
	out := make(map[string]bool, len(seeds))
	for id := range seeds {
		out[id] = true
	}
	for round := 0; round < 8; round++ {
		grew := false
		for _, f := range fn.Flows {
			if out[f.From] && !out[f.To] {
				out[f.To] = true
				grew = true
			}
		}
		for _, v := range fn.Values {
			if v.Kind == ir.ValueProperty && v.Base != "" && out[v.Base] && !out[v.ID] {
				out[v.ID] = true
				grew = true
			}
		}
		if callResults {
			for _, c := range fn.Calls {
				if c.ResultID == "" || out[c.ResultID] || carried(c, out) == nil {
					continue
				}
				out[c.ResultID] = true
				grew = true
			}
		}
		if !grew {
			break
		}
	}
	return out
}

// recordReach is everything the function computed FROM the record, calls included.
//
// A row fetched with the identifier is that row -- `Attribute.objects.get(pk=pk)` and
// `AttributeValue.objects.filter(pk=pk).values_list("attribute__type")` are both about
// the record the caller named, and saleor's attribute mutations relate exactly those to
// the requester. Without following the call there is no record left to relate by the time
// the check is made, and three correct mutations read as unchecked.
func recordReach(fn *ir.Function, seeds map[string]bool) map[string]bool {
	return reach(fn, seeds, true)
}

// requestReach is everything the function computed from the REQUEST that is still the
// requester, and calls are followed only where the program says the answer is one.
//
// The asymmetry with recordReach is the whole precision of this rule. Anything computed
// from a row is about that row, but a great many things are computed FROM a request
// without being the caller: `get_site_promise(info.context).get()` is the site's
// configuration and `get_plugin_manager_promise(info.context).get()` is a plugin
// registry. Treating those as the requester makes every call that carries one alongside
// the record look like an authorization, and saleor hands a `site` to the very call that
// reads the unowned order.
//
// So a call result joins the set only when every value it was built from is already the
// request AND the program names the answer for what it is -- `requestor =
// get_user_or_app_from_context(info.context)`, which is the spelling saleor's shipping
// mutation uses to relate the checkout to the caller.
func requestReach(fn *ir.Function, seeds map[string]bool,
	shape *model.UndeclaredScope, values map[string]*ir.Value) map[string]bool {

	out := reach(fn, seeds, false)
	for round := 0; round < 4; round++ {
		grew := false
		for _, c := range fn.Calls {
			if c.ResultID == "" || out[c.ResultID] || len(c.Args) == 0 {
				continue
			}
			built := true
			for _, a := range c.Args {
				if a.ValueID != "" && !out[a.ValueID] {
					built = false
					break
				}
			}
			if !built || !namesActor(fn, c, shape, values) {
				continue
			}
			out[c.ResultID] = true
			grew = true
		}
		if !grew {
			break
		}
		out = reach(fn, out, false)
	}
	return out
}

// namesActor reports whether the program calls this answer the requester -- on the call
// it made, or on the name it bound the result to.
func namesActor(fn *ir.Function, c *ir.Call, shape *model.UndeclaredScope,
	values map[string]*ir.Value) bool {

	names := []string{leafOfName(c.Callee.Symbol), c.Method, leafOfName(c.Callee.Name)}
	for _, f := range fn.Flows {
		if f.From != c.ResultID {
			continue
		}
		if v := values[f.To]; v != nil {
			names = append(names, v.Name)
		}
	}
	for _, n := range names {
		if n == "" {
			continue
		}
		lower := strings.ToLower(n)
		for _, w := range shape.ActorWords {
			if strings.Contains(lower, w) {
				return true
			}
		}
	}
	return false
}

// relatesRecord reports whether the mutation brings the record and the requester
// together.
//
// One call handed both is the relation, and it is how saleor states it every time it
// states it: `check_attribute_type_permissions(cls, info.context, [attribute.type])`,
// `check_can_edit_address(info.context, address)`, `fetch_shipping_methods_for_checkout(
// checkout_info, requestor=requestor)`. A call handed only the request is NOT -- that is
// the presumption `authorization-scoped-elsewhere` exists to replace, and it is satisfied
// by every `get_plugin_manager_promise(info.context)` in the file. A call handed only the
// record is not either: fetching a row proves it is there and says nothing about who may
// have it.
//
// The descent follows the record into the mutation's own callees, and asks the question
// again from inside. saleor's address delete resolves the row in `perform_mutation` and
// relates it to the requester one method along:
//
//	instance = cls.get_node_or_error(info, id, only_type=Address)
//	cls.clean_instance(info, instance)          # and clean_instance asks
//	    -> check_can_edit_address(info.context, instance)
//
// The request is SEEDED AFRESH inside the callee rather than carried into it, and that is
// deliberate. Carrying it would mean accepting `cls.create_checkout(info, order)` as
// evidence -- the framework's whole resolver context travels with every call a graphene
// mutation makes, so a rule that read it as "the request went too" would find a relation
// in every mutation ever written. What the callee has is `info.context`, and whether it
// asks anything with it is exactly the question.
func relatesRecord(ix *ir.Index, fn *ir.Function, sel *ir.Call, record map[string]bool,
	identity taint.Classified, shape *model.UndeclaredScope, depth int) bool {

	values := valuesOf(fn)
	request := requestReach(fn, requestSeeds(fn, identity, shape), shape, values)
	if compared(fn, record, identity) {
		return true
	}
	for _, c := range fn.Calls {
		if c.ID == sel.ID {
			continue
		}
		hasRecord := carried(c, record)
		if hasRecord != nil && carried(c, request) != nil {
			return true
		}
		if depth >= shape.Depth || hasRecord == nil {
			continue
		}
		callee := ix.FuncByID[c.Callee.FunctionID]
		if callee == nil || callee.ID == fn.ID || len(callee.Params) == 0 {
			continue
		}
		inner := mapInto(callee, c, record)
		if len(inner) == 0 {
			continue
		}
		if relatesRecord(ix, callee, sel,
			recordReach(callee, inner),
			identity, shape, depth+1) {
			return true
		}
	}
	return false
}

func valuesOf(fn *ir.Function) map[string]*ir.Value {
	out := make(map[string]*ir.Value, len(fn.Values))
	for _, v := range fn.Values {
		out[v.ID] = v
	}
	return out
}

// mapInto carries a set of values across a call boundary, onto the parameters they were
// bound to.
func mapInto(callee *ir.Function, c *ir.Call, set map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, a := range c.Args {
		if a.ValueID == "" || !set[a.ValueID] {
			continue
		}
		for _, p := range a.BoundParams(callee) {
			if p.ValueID != "" {
				out[p.ValueID] = true
			}
		}
	}
	return out
}

// carried reports which argument of a call, or its receiver, holds a value from the set.
func carried(c *ir.Call, set map[string]bool) *ir.Arg {
	if c.ReceiverID != "" && set[c.ReceiverID] {
		return &ir.Arg{ValueID: c.ReceiverID, Index: -1}
	}
	for i := range c.Args {
		if c.Args[i].ValueID != "" && set[c.Args[i].ValueID] {
			return &c.Args[i]
		}
	}
	return nil
}

// compared reports whether the mutation tested something about the record against the
// caller. `if order.user != info.context.user: raise PermissionDenied()` is the relation
// written as a branch rather than as a call, and this analysis has nothing to say about
// a mutation that wrote it.
func compared(fn *ir.Function, record map[string]bool, identity taint.Classified) bool {
	for _, cmp := range fn.Comparisons {
		if (record[cmp.Left] && identity.Values[cmp.Right]) ||
			(record[cmp.Right] && identity.Values[cmp.Left]) {
			return true
		}
	}
	return false
}

// typeName is the subject a reader would call the decoded record, taken from the package
// its type is defined in: `saleor.graphql.order.types` is an order.
func typeName(subject string) string {
	if i := strings.LastIndexByte(subject, '.'); i > 0 {
		rest := subject[:i]
		if j := strings.LastIndexByte(rest, '.'); j >= 0 && j+1 < len(rest) {
			return rest[j+1:] + " record"
		}
	}
	return "record"
}

func leafOfName(s string) string {
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func undeclaredFinding(ix *ir.Index, fn *ir.Function, ep *ir.EntryPoint,
	rule model.ScopeRule, sel *ir.Call, named, subject string) taint.Finding {

	operation := ep.Detail["path"]
	if operation == "" {
		operation = fn.Name
	}
	handler := ep.Detail["handler"]
	if handler == "" {
		handler = fn.Name
	}
	label := "the operation's own argument"
	for _, v := range fn.Values {
		if v.ID == named && v.Name != "" {
			label = v.Name
			break
		}
	}
	symbol := sel.Callee.Symbol
	if symbol == "" {
		symbol = sel.Method
	}
	if symbol == "" {
		if callee := ix.FuncByID[sel.Callee.FunctionID]; callee != nil {
			symbol = callee.Name
		}
	}
	return taint.Finding{
		Analysis:   rule.ID,
		DataClass:  "record-selector",
		ChannelID:  rule.ID,
		Class:      rule.Finding,
		CWE:        rule.CWE,
		Message:    rule.Reason,
		Confidence: taint.Medium,

		SourceLabel: label,
		SourceLoc:   ep.Loc,

		EntryPoint:    ep.Detail["method"] + " " + operation,
		EntryAnchored: true,
		EntryTrust:    ep.TrustLevel(),
		InTestModule:  ix.InTestModule(sel.Loc),

		SinkLoc:      sel.Loc,
		SinkSymbol:   symbol,
		SinkFunction: fn.Name,
		SinkArgIndex: -1,
		SinkContext:  "record-selector",
		SinkRational: rule.Rationale,

		Path: []taint.Hop{
			{
				Loc: ep.Loc,
				Description: fmt.Sprintf(
					"%s declares no %s, so the framework's check admits every caller",
					handler, rule.Undeclared.Control),
				Resolution: ir.Resolved,
			},
			{
				Loc: sel.Loc,
				Description: fmt.Sprintf(
					"`%s` is a global identifier the request carried, and %s() decodes it into a %s -- which is not this operation's own subject, so the empty declaration above said nothing about it",
					label, leafOfName(symbol), typeName(subject)),
				Resolution: sel.Callee.Resolution,
			},
			{
				Loc: fn.Loc,
				Description: fmt.Sprintf(
					"nothing in %s brings that record and the requester together", handler),
				Resolution: ir.Resolved,
			},
		},
	}
}
