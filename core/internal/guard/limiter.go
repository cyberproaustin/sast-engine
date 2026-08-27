package guard

import (
	"fmt"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

type routeConstraint struct {
	value string
	equal bool
	loc   ir.Loc
}

type requestConstraint struct {
	transport string
	field     string
	value     string
	equal     bool
	loc       ir.Loc
}

type limiterAdmission struct {
	paths []routeConstraint
	attrs []requestConstraint
	loc   ir.Loc
}

func analyzeLimiters(d *ir.IR, m model.Model) []taint.Finding {
	ix := ir.NewIndex(d)
	var out []taint.Finding
	for _, rule := range m.Guards {
		if rule.Limiter == nil {
			continue
		}
		if rule.Limiter.BucketKey != nil {
			out = append(out, analyzeBucketKey(ix, rule)...)
		}
		if rule.Limiter.KeyFromHeader != nil {
			out = append(out, analyzeKeyFromHeader(ix, rule)...)
		}
		if len(rule.Limiter.Counters) != 0 {
			out = append(out, analyzeLimiterCoverage(ix, m, rule)...)
		}
	}
	return out
}

func analyzeBucketKey(ix *ir.Index, rule model.GuardRule) []taint.Finding {
	lr, key := rule.Limiter, rule.Limiter.BucketKey
	var constructors []*ir.Call
	for _, fn := range ix.IR.Functions {
		for _, call := range fn.Calls {
			if ix.InTestModule(call.Loc) || !matchesCall(call, lr.Constructors) {
				continue
			}
			if hasOption(call, key.OverrideOption, "") {
				continue
			}
			if key.Validation != "" && !hasOption(call, key.Validation, key.ValidationOff) {
				continue
			}
			constructors = append(constructors, call)
		}
	}
	if len(constructors) == 0 {
		return nil
	}

	var out []taint.Finding
	for _, fn := range ix.IR.Functions {
		for _, call := range fn.Calls {
			if ix.InTestModule(call.Loc) || call.Method != key.TrustMethod {
				continue
			}
			if !strings.EqualFold(call.ArgLiterals[0], key.TrustKey) ||
				!oneOfFold(call.ArgLiterals[1], key.TrustedValues) {
				continue
			}
			constructor := constructors[0]
			out = append(out, taint.Finding{
				Analysis:      rule.ID,
				Class:         rule.Finding,
				CWE:           rule.CWE,
				Message:       rule.Reason,
				Confidence:    taint.High,
				SourceLoc:     constructor.Loc,
				SourceLabel:   "default " + key.Default + " bucket key",
				EntryAnchored: true,
				SinkLoc:       call.Loc,
				SinkFunction:  fn.ID,
				SinkSymbol:    key.TrustMethod + "(" + key.TrustKey + ")",
				SinkRational:  rule.Rationale,
				RelatedSites: []taint.Site{{
					Loc: constructor.Loc,
				}},
			})
		}
	}
	return out
}

// analyzeKeyFromHeader reports a rate limiter whose key the caller writes.
//
// The rule beside this one reads a CONFIGURATION -- express-rate-limit's default key
// under `app.set("trust proxy", true)` -- and is silent on an application that supplies
// a key of its own, because neither the library nor the framework setting it names is
// present. This reads the KEY instead, out of three facts the graph already holds: the
// module builds a limiter, a function in it is that limiter's key, and the key reaches a
// forwarding header.
//
// Scoped to one module on purpose. A function called `key` is an ordinary thing to write
// and says nothing on its own; a function called `key` in the file that constructs the
// limiters is the bucket key, and that is the whole of the claim.
func analyzeKeyFromHeader(ix *ir.Index, rule model.GuardRule) []taint.Finding {
	kr := rule.Limiter.KeyFromHeader

	// The noise boundary, and the same one the coverage rule draws: without a limiter
	// construction in the module, nothing here is about rate limiting at all.
	limiters := map[string]*ir.Call{}
	for _, fn := range ix.IR.Functions {
		for _, call := range fn.Calls {
			if ix.InTestModule(call.Loc) || !ix.InApplicationSurface(call.Loc) {
				continue
			}
			if !carriesWord(call.Callee.Name, kr.Vocabulary) &&
				!carriesWord(lastSegment(call.Callee.Symbol), kr.Vocabulary) {
				continue
			}
			if _, seen := limiters[call.Loc.File]; !seen {
				limiters[call.Loc.File] = call
			}
		}
	}
	if len(limiters) == 0 {
		return nil
	}

	var out []taint.Finding
	for _, fn := range ix.IR.Functions {
		constructor := limiters[fn.Loc.File]
		if constructor == nil || !nameIn(fn.Name, kr.KeyOptions) {
			continue
		}
		if ix.InTestModule(fn.Loc) || !ix.InApplicationSurface(fn.Loc) {
			continue
		}
		read := firstForwardedHeaderRead(ix, fn.ID, kr, moduleScope(ix), map[string]bool{})
		if read == nil {
			continue
		}
		out = append(out, taint.Finding{
			Analysis:      rule.ID,
			Class:         rule.Finding,
			CWE:           rule.CWE,
			Message:       rule.Reason,
			Confidence:    taint.High,
			SourceLoc:     constructor.Loc,
			SourceLabel:   fn.Name + " decides the rate-limit bucket",
			EntryAnchored: true,
			SinkLoc:       read.Loc,
			SinkFunction:  fn.ID,
			SinkSymbol:    "header(" + read.Header + ")",
			SinkRational:  rule.Rationale,
			RelatedSites: []taint.Site{{
				Loc: constructor.Loc,
			}},
		})
	}
	return out
}

// headerRead is one place a forwarding header was named, and which one it was.
type headerRead struct {
	Loc    ir.Loc
	Header string
}

// firstForwardedHeaderRead walks out from the key function looking for a place a
// forwarding header is named.
//
// Names, not accessors. An application reads a header through `headers.get(name)`,
// `req.headers[name]`, `req.get(name)` and `META["HTTP_X_FORWARDED_FOR"]`, and
// enumerating those is a list that goes wrong at the next framework -- while the header's
// own NAME is the same string in all of them. reactive-resume never writes the name at
// the call at all: it loops over a module-level `TRUSTED_IP_HEADERS` array in another
// package, so the literal is found by walking the value graph backwards from the
// argument rather than by reading the call.
func firstForwardedHeaderRead(ix *ir.Index, root string, kr *model.KeyFromHeaderRule,
	defined map[string][]string, seen map[string]bool) *headerRead {
	if seen[root] {
		return nil
	}
	seen[root] = true
	fn := ix.FuncByID[root]
	if fn == nil {
		return nil
	}
	// `req.headers["x-forwarded-for"]` is a property rather than a call, and the header
	// is the last segment of the path.
	for _, value := range fn.Values {
		if value.Kind != ir.ValueProperty {
			continue
		}
		if header := matchingHeader(lastSegment(value.Path), kr.ForwardingHeaders); header != "" {
			return &headerRead{Loc: value.Loc, Header: header}
		}
	}
	for _, call := range fn.Calls {
		for _, literal := range call.ArgLiterals {
			if header := matchingHeader(literal, kr.ForwardingHeaders); header != "" {
				return &headerRead{Loc: call.Loc, Header: header}
			}
		}
		for _, arg := range call.Args {
			if header := literalBehind(ix, arg.ValueID, kr.ForwardingHeaders, defined); header != "" {
				return &headerRead{Loc: call.Loc, Header: header}
			}
		}
		for _, target := range callTargets(call) {
			if read := firstForwardedHeaderRead(ix, target, kr, defined, seen); read != nil {
				return read
			}
		}
	}
	return nil
}

// literalBehind walks the flow graph backwards from a value collecting the literals it
// was built from, and answers with the first that names a forwarding header.
//
// Bounded, and bounded tightly: this runs once per argument of every call reachable from
// a key function, and a value in a large program is reachable from a great many others.
func literalBehind(ix *ir.Index, id string, headers []string, defined map[string][]string) string {
	// The whole walk rather than the first hit, so the header REPORTED is the one the
	// model names first rather than whichever the value graph reached first. An
	// application that tries several in turn reads all of them, and a finding that says
	// `cf-connecting-ip` invites the reader to answer "but we are behind Cloudflare"
	// about a list whose next entry is `x-forwarded-for`.
	best := len(headers)
	seen := map[string]bool{}
	frontier := []string{id}
	for depth := 0; depth < 8 && len(frontier) != 0; depth++ {
		var next []string
		for _, at := range frontier {
			if at == "" || seen[at] {
				continue
			}
			seen[at] = true
			value := ix.ValueByID[at]
			if value == nil {
				continue
			}
			if at := headerIndex(value.Literal, headers); at < best {
				best = at
			}
			incoming := 0
			if owner := ix.OwnerOfValue[at]; owner != nil {
				for _, edge := range owner.Flows {
					if edge.To == at {
						incoming++
						next = append(next, edge.From)
					}
				}
			}
			// An imported constant is a dangling name. Neither frontend links
			// `import { TRUSTED_IP_HEADERS } from "..."` to the array the other module
			// declares, so the reference has a name, no literal and nothing flowing into
			// it, and a backwards walk stops there -- which is exactly where
			// reactive-resume keeps its header list. Continuing at the module-level
			// declaration of that name is resolving the import, and it is done here
			// rather than in the frontend because linking every imported binding would
			// change what taint reaches everywhere, which is a larger change than this
			// rule should make on its own.
			if incoming == 0 && value.Literal == "" {
				next = append(next, defined[value.Name]...)
			}
		}
		frontier = next
	}
	if best == len(headers) {
		return ""
	}
	return headers[best]
}

// moduleScope indexes the module-level values of the whole program by the name they were
// declared under, so a free reference can be resolved to what it names.
//
// Module level only, and named values only: a local of the same name in some unrelated
// function is not what an import resolves to, and `{object}` is the frontend's word for
// a value with no name at all.
func moduleScope(ix *ir.Index) map[string][]string {
	out := map[string][]string{}
	for _, fn := range ix.IR.Functions {
		if fn.Name != "<module>" {
			continue
		}
		for _, value := range fn.Values {
			name := value.Name
			if name == "" || strings.HasPrefix(name, "{") || strings.HasPrefix(name, "[") {
				continue
			}
			out[name] = append(out[name], value.ID)
		}
	}
	return out
}

// matchingHeader compares a written string with the header names, ignoring case and the
// separators a header name is spelled with. `X-Forwarded-For`, `x_forwarded_for` and
// Django's `HTTP_X_FORWARDED_FOR` are one header written three ways.
func matchingHeader(written string, headers []string) string {
	if at := headerIndex(written, headers); at < len(headers) {
		return headers[at]
	}
	return ""
}

// headerIndex returns the position of the header this string names, or len(headers).
func headerIndex(written string, headers []string) int {
	got := normalizeHeader(written)
	if got == "" {
		return len(headers)
	}
	got = strings.TrimPrefix(got, "http")
	for i, header := range headers {
		if got == normalizeHeader(header) {
			return i
		}
	}
	return len(headers)
}

func normalizeHeader(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + ('a' - 'A'))
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
		}
	}
	return b.String()
}

// carriesWord reports whether a name contains one of these words once case and the
// separators a name is written with are removed. The same comparison the CSRF control
// list uses, and for the same reason: every spelling a project chooses contains the word.
func carriesWord(name string, words []string) bool {
	got := normalizeHeader(name)
	if got == "" {
		return false
	}
	for _, word := range words {
		if strings.Contains(got, normalizeHeader(word)) {
			return true
		}
	}
	return false
}

func analyzeLimiterCoverage(ix *ir.Index, m model.Model, rule model.GuardRule) []taint.Finding {
	lr := rule.Limiter
	var admissions []limiterAdmission
	for _, fn := range ix.IR.Functions {
		for _, call := range fn.Calls {
			if ix.InTestModule(call.Loc) || !nameIn(call.Method, lr.MountMethods) {
				continue
			}
			for _, arg := range call.Args {
				if arg.FunctionID == "" {
					continue
				}
				admissions = append(admissions, admissionsFrom(ix, rule, arg.FunctionID, call.Loc)...)
			}
		}
	}
	// This is the noise boundary: without a bucket-consuming call reachable from a
	// mounted control, the application has not demonstrated that it rate-limits at all.
	if len(admissions) == 0 {
		return nil
	}

	var out []taint.Finding
	for _, ep := range ix.IR.EntryPoints {
		if ep.Framework != lr.Framework {
			continue
		}
		fn := ix.FuncByID[ep.FunctionID]
		if fn == nil || !ix.InApplicationSurface(fn.Loc) {
			continue
		}
		expensive := firstExpensiveCall(ix, m, lr, fn.ID)
		if expensive == nil || routeCovered(ix, ep, expensive, admissions, lr) {
			continue
		}
		at := admissionEvidence(ep, admissions)
		label := strings.TrimSpace(ep.Detail["method"] + " " + ep.Detail["path"])
		out = append(out, taint.Finding{
			Analysis:      rule.ID,
			Class:         rule.Finding,
			CWE:           rule.CWE,
			Message:       fmt.Sprintf("%s; %s reaches %s at %s", rule.Reason, label, callName(ix, expensive), expensive.Loc),
			Confidence:    taint.High,
			SourceLoc:     expensive.Loc,
			SourceLabel:   label + " reaches expensive work",
			EntryPoint:    label,
			EntryMethod:   ep.Detail["method"],
			EntryPath:     ep.Detail["path"],
			EntryAnchored: true,
			// The entry point IS the subject here -- this route reaches expensive work
			// with nothing admitting it -- so who can reach the route is the finding's
			// own trust. Unstated, it would read as remote, which is the right default
			// for a route and the wrong one for anything else that ever grows a limiter.
			EntryTrust:   ep.TrustLevel(),
			SinkLoc:      at.loc,
			SinkFunction: fn.ID,
			SinkSymbol:   "rate-limit admission predicate",
			SinkRational: rule.Rationale,
			RelatedSites: []taint.Site{{
				Loc: expensive.Loc,
			}},
		})
	}
	return out
}

func admissionsFrom(ix *ir.Index, rule model.GuardRule, root string, mount ir.Loc) []limiterAdmission {
	lr := rule.Limiter
	var out []limiterAdmission
	seen := map[string]bool{}
	var visit func(string, []routeConstraint, []requestConstraint)
	visit = func(id string, paths []routeConstraint, attrs []requestConstraint) {
		key := id + constraintsKey(paths, attrs)
		if seen[key] {
			return
		}
		seen[key] = true
		fn := ix.FuncByID[id]
		if fn == nil {
			return
		}
		graph := cfg.Build(fn)
		for _, call := range fn.Calls {
			callPaths, callAttrs := append([]routeConstraint{}, paths...), append([]requestConstraint{}, attrs...)
			if graph != nil && call.Block != "" {
				p, a := predicatesForCall(ix, fn, graph, call, lr)
				callPaths, callAttrs = append(callPaths, p...), append(callAttrs, a...)
			}
			if matchesCall(call, lr.Counters) {
				loc := mount
				if len(callPaths) != 0 {
					loc = callPaths[len(callPaths)-1].loc
				} else if len(callAttrs) != 0 {
					loc = callAttrs[len(callAttrs)-1].loc
				}
				out = append(out, limiterAdmission{paths: callPaths, attrs: callAttrs, loc: loc})
			}
			for _, target := range callTargets(call) {
				visit(target, callPaths, callAttrs)
			}
		}
	}
	visit(root, nil, nil)
	return out
}

func predicatesForCall(ix *ir.Index, fn *ir.Function, graph *cfg.Graph, call *ir.Call, lr *model.LimiterGuard) ([]routeConstraint, []requestConstraint) {
	var paths []routeConstraint
	var attrs []requestConstraint
	for _, cmp := range fn.Comparisons {
		if cmp.Block == "" || !graph.ControlDependsOn(call.Block, cmp.Block) {
			continue
		}
		leftPath, leftField := requestAccess(ix, fn, cmp.Left, lr)
		rightPath, rightField := requestAccess(ix, fn, cmp.Right, lr)
		literal, access, field := literalValue(ix, cmp.Right), leftPath, leftField
		if literal == "" {
			literal, access, field = literalValue(ix, cmp.Left), rightPath, rightField
		}
		if literal == "" || access == "" {
			continue
		}
		trueArm := graph.DependsOnSuccessor(call.Block, cmp.Block, 0)
		equal := cmp.Op == "Eq" || cmp.Op == "Is"
		if !trueArm {
			equal = !equal
		}
		if nameIn(access, lr.PathAttributes) {
			paths = append(paths, routeConstraint{value: literal, equal: equal, loc: cmp.Loc})
			continue
		}
		for _, attr := range lr.RequestAttributes {
			if access == attr.Path {
				attrs = append(attrs, requestConstraint{
					transport: attr.Transport,
					field:     field,
					value:     literal,
					equal:     equal,
					loc:       cmp.Loc,
				})
			}
		}
	}
	return paths, attrs
}

func requestAccess(ix *ir.Index, fn *ir.Function, id string, lr *model.LimiterGuard) (string, string) {
	value := ix.ValueByID[id]
	if value == nil {
		return "", ""
	}
	if value.Kind == ir.ValueProperty {
		parts := strings.Split(value.Path, ".")
		for _, part := range parts {
			if nameIn(part, lr.PathAttributes) {
				return part, ""
			}
			for _, attr := range lr.RequestAttributes {
				if part == attr.Path {
					field := ""
					if len(parts) > 1 {
						field = parts[len(parts)-1]
					}
					return part, field
				}
			}
		}
	}
	for _, call := range fn.Calls {
		if call.ResultID != id {
			continue
		}
		receiver := ix.ValueByID[call.ReceiverID]
		if receiver == nil {
			return "", ""
		}
		access, _ := requestAccess(ix, fn, receiver.ID, lr)
		if access == "" {
			return "", ""
		}
		return access, call.ArgLiterals[0]
	}
	return "", ""
}

func routeCovered(ix *ir.Index, ep ir.EntryPoint, expensive *ir.Call, admissions []limiterAdmission, lr *model.LimiterGuard) bool {
	path := ep.Detail["path"]
	workAttrs := requestPredicatesAt(ix, expensive, lr)
	for _, admission := range admissions {
		matches := true
		for _, constraint := range admission.paths {
			if (path == constraint.value) != constraint.equal {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		if len(admission.attrs) == 0 {
			return true
		}
		// A partial limiter still covers the expensive operation when the operation is
		// gated by the SAME request fact. Transport is part of that identity: Flask args
		// and form may carry equal field names, but one is query-only and the other is
		// body-only.
		all := true
		for _, want := range admission.attrs {
			found := false
			for _, got := range workAttrs {
				if want.transport == got.transport && want.field == got.field &&
					want.value == got.value && want.equal == got.equal {
					found = true
					break
				}
			}
			if !found {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func admissionEvidence(ep ir.EntryPoint, admissions []limiterAdmission) limiterAdmission {
	for _, admission := range admissions {
		matches := true
		for _, constraint := range admission.paths {
			if (ep.Detail["path"] == constraint.value) != constraint.equal {
				matches = false
				break
			}
		}
		if matches && len(admission.attrs) != 0 {
			copy := admission
			copy.loc = admission.attrs[len(admission.attrs)-1].loc
			return copy
		}
	}
	for _, admission := range admissions {
		for _, constraint := range admission.paths {
			if (ep.Detail["path"] == constraint.value) != constraint.equal {
				return admission
			}
		}
	}
	return admissions[0]
}

func requestPredicatesAt(ix *ir.Index, call *ir.Call, lr *model.LimiterGuard) []requestConstraint {
	fn := ix.OwnerOfCall[call.ID]
	if fn == nil || call.Block == "" {
		return nil
	}
	graph := cfg.Build(fn)
	if graph == nil {
		return nil
	}
	_, attrs := predicatesForCall(ix, fn, graph, call, lr)
	return attrs
}

func firstExpensiveCall(ix *ir.Index, m model.Model, lr *model.LimiterGuard, root string) *ir.Call {
	wanted := map[string]bool{}
	for _, id := range lr.ExpensiveChannels {
		wanted[id] = true
	}
	seen := map[string]bool{root: true}
	queue := []string{root}
	for len(queue) != 0 {
		id := queue[0]
		queue = queue[1:]
		fn := ix.FuncByID[id]
		if fn == nil {
			continue
		}
		for _, call := range fn.Calls {
			if expensiveCall(ix, m, lr, wanted, call) {
				return call
			}
			// A dispatch is the operation the route performs once per request. Its target
			// set proves what that operation costs, but reporting one arbitrarily sorted
			// backend would hide the per-request call that matters.
			if len(call.Callee.PossibleFunctionIDs) != 0 &&
				anyTargetIsExpensive(ix, m, lr, wanted, call.Callee.PossibleFunctionIDs, map[string]bool{}) {
				return call
			}
			for _, target := range callTargets(call) {
				if !seen[target] {
					seen[target] = true
					queue = append(queue, target)
				}
			}
		}
	}
	return nil
}

func anyTargetIsExpensive(ix *ir.Index, m model.Model, lr *model.LimiterGuard, wanted map[string]bool, targets []string, seen map[string]bool) bool {
	for _, target := range targets {
		if seen[target] {
			continue
		}
		seen[target] = true
		fn := ix.FuncByID[target]
		if fn == nil {
			continue
		}
		for _, call := range fn.Calls {
			if expensiveCall(ix, m, lr, wanted, call) {
				return true
			}
			if anyTargetIsExpensive(ix, m, lr, wanted, callTargets(call), seen) {
				return true
			}
		}
	}
	return false
}

func expensiveCall(ix *ir.Index, m model.Model, lr *model.LimiterGuard, wanted map[string]bool, call *ir.Call) bool {
	for _, channel := range m.ChannelsMatching(call.Callee.Symbol, call.Method) {
		if wanted[channel.ID] {
			return true
		}
	}
	return nameIn(callName(ix, call), lr.URLMethods) && callHasURL(ix, call)
}

func callTargets(call *ir.Call) []string {
	out := append([]string{}, call.Callee.PossibleFunctionIDs...)
	if call.Callee.FunctionID != "" {
		out = append(out, call.Callee.FunctionID)
	}
	return out
}

func callHasURL(ix *ir.Index, call *ir.Call) bool {
	for _, literal := range call.ArgLiterals {
		if strings.Contains(literal, "http://") || strings.Contains(literal, "https://") {
			return true
		}
	}
	for _, arg := range call.Args {
		seen := map[string]bool{}
		queue := []string{arg.ValueID}
		for len(queue) != 0 && len(seen) < 128 {
			id := queue[0]
			queue = queue[1:]
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			if value := ix.ValueByID[id]; value != nil && (strings.Contains(value.Literal, "http://") || strings.Contains(value.Literal, "https://")) {
				return true
			}
			if owner := ix.OwnerOfValue[id]; owner != nil {
				for _, edge := range owner.Flows {
					if edge.To == id {
						queue = append(queue, edge.From)
					}
				}
			}
		}
	}
	return false
}

func literalValue(ix *ir.Index, id string) string {
	if value := ix.ValueByID[id]; value != nil && value.Kind == ir.ValueLiteral {
		return value.Literal
	}
	return ""
}

func constraintsKey(paths []routeConstraint, attrs []requestConstraint) string {
	var b strings.Builder
	for _, path := range paths {
		fmt.Fprintf(&b, "|p:%t:%s", path.equal, path.value)
	}
	for _, attr := range attrs {
		fmt.Fprintf(&b, "|a:%s:%s:%t:%s", attr.transport, attr.field, attr.equal, attr.value)
	}
	return b.String()
}

func matchesCall(call *ir.Call, names []string) bool {
	for _, name := range names {
		if strings.Contains(name, ".") {
			if call.Callee.Symbol == name {
				return true
			}
			continue
		}
		if nameIn(call.Callee.Symbol, []string{name}) ||
			nameIn(call.Callee.Name, []string{name}) ||
			nameIn(call.Method, []string{name}) {
			return true
		}
	}
	return false
}

func nameIn(got string, names []string) bool {
	got = lastSegment(got)
	for _, name := range names {
		if got == lastSegment(name) {
			return true
		}
	}
	return false
}

func hasOption(call *ir.Call, key, value string) bool {
	for _, literal := range call.ArgLiterals {
		writtenKey, writtenValue, ok := strings.Cut(literal, "=")
		if !ok || !strings.EqualFold(lastSegment(writtenKey), key) {
			continue
		}
		return value == "" || strings.EqualFold(writtenValue, value)
	}
	return false
}

func oneOfFold(got string, values []string) bool {
	for _, value := range values {
		if strings.EqualFold(got, value) {
			return true
		}
	}
	return false
}
