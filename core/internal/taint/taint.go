// Package taint is the core dataflow analysis. It consumes only the IR and the
// security model, and knows nothing about any language.
//
// Every finding it produces carries the path that justifies it (ADR-006), and its
// confidence is derived from how well the call edges along that path resolved, not
// from the seriousness of the vulnerability class (ADR-005).
package taint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
)

// Confidence is how well the engine resolved the path it is reporting.
type Confidence string

const (
	// High: every call edge on the path resolved to a declaration.
	High Confidence = "high"
	// Medium: the path crosses at least one probable (heuristic) edge.
	Medium Confidence = "medium"
	// Low: the path crosses an unresolved dynamic dispatch.
	Low Confidence = "low"
)

// Gating reports whether a finding at this confidence may fail a pipeline.
func (c Confidence) Gating() bool { return c == High }

// Hop is one step of the evidence path.
type Hop struct {
	Loc         ir.Loc
	Description string
	Symbol      string // external symbol traversed at this hop, if any
	Kind        string // the IR flow kind this hop came from, when it came from a flow
	Resolution  ir.Resolution
}

// composedIntoText reports whether the value was built into a larger piece of text on
// its way to the sink, rather than passed along whole.
func composedIntoText(path []Hop) bool {
	for _, h := range path {
		if h.Kind == "template" || h.Kind == "binary" {
			return true
		}
	}
	return false
}

// Sanitizer records a sanitizer the taint actually passed through, and whether it
// was sufficient for the sink's context.
type Sanitizer struct {
	Symbol   string
	Loc      ir.Loc
	Clears   bool
	Note     string
	Required string // the sink context it needed to clear
}

// Finding is a reported dataflow from an untrusted source to a dangerous sink.
type Finding struct {
	Analysis string // the policy that was violated

	// The three-part judgement that produced this finding (ADR-012): a value of this
	// class reached a channel with this visibility, and policy forbids the pairing.
	DataClass  string
	ChannelID  string
	Visibility string

	Class      string
	CWE        string
	Message    string
	Confidence Confidence

	SourceLoc   ir.Loc
	SourceLabel string
	EntryPoint  string
	EntryMethod string
	EntryPath   string
	// EntryAnchored reports whether this flow reaches an entry point the engine
	// actually enumerated. An unanchored finding is not an assertion over the
	// surface (ADR-009): it is reported, but it never gates.
	EntryAnchored bool
	// InTestModule marks a finding in code that ships with the repository but does not
	// run in production. Reported, never gating: a key written into a test is in the
	// history exactly as the reason says and is still not a production credential.
	InTestModule bool
	// DependsOnUse marks a finding whose judgement turns on what the result is used for,
	// which the analysis that produced it cannot see. Reported, never gating.
	DependsOnUse bool
	// EntryHasNoInjectedIdentity marks a finding on an entry point that was handed no
	// caller identity, in a program where identity IS injected elsewhere. Reported so
	// that login flows, OAuth callbacks and invite redemptions can be recognized as a
	// group rather than read one at a time. It changes no judgement and no gate.
	//
	// Set only for judgements that turn on the caller's identity. A response leaking an
	// internal error is equally wrong on a login endpoint, and grouping it here would
	// suggest a remedy that does not apply to it.
	EntryHasNoInjectedIdentity bool

	SinkLoc      ir.Loc
	SinkFunction string
	SinkSymbol   string
	SinkArgIndex int
	SinkContext  string
	SinkRational string

	Path       []Hop
	Sanitizers []Sanitizer
}

// Result is the outcome of an analysis run. An analysis whose capability
// requirements are unmet is NOT APPLICABLE and reports no findings — which is a
// distinct outcome from having run and found nothing (ADR-003).
type Result struct {
	Applicable          bool
	MissingCapabilities []string
	Findings            []Finding
	Unjudged            []Unjudged
	// Skipped records policies that could not be evaluated. An unevaluated policy is
	// not a satisfied one (ADR-003).
	Skipped []SkippedPolicy
	// NoCallerIdentity holds judgements about the caller's identity made where the
	// framework handed the entry point none. Reported, never counted, never gating.
	NoCallerIdentity []Finding
}

// SkippedPolicy is a judgement the engine declined to make.
type SkippedPolicy struct {
	PolicyID string
	Missing  []string
}

// Unjudged is a policy that could not coherently apply to a specific flow. It is
// reported rather than dropped: "this could not be judged" is information, and
// silence would be indistinguishable from "this was fine".
type Unjudged struct {
	PolicyID   string
	EntryPoint string
	Loc        ir.Loc
	Reason     string
}

// edge records how a value became tainted, forming the evidence chain.
type edge struct {
	from       string
	kind       string
	desc       string
	loc        ir.Loc
	symbol     string
	resolution ir.Resolution
}

type engine struct {
	ix    *ir.Index
	m     model.Model
	class model.Classification

	tainted      map[string]bool
	pred         map[string]edge
	seeds        map[string]seed
	skipped      map[string][]string
	unjudged     []Unjudged
	saidUnjudged map[string]bool
	// unjudgedIdentity holds findings whose judgement turned on a caller identity the
	// entry point was never given. Reported separately, never as findings.
	unjudgedIdentity []Finding

	programInjects bool

	argUses      map[string][]*ir.Call // value ID -> call sites using it as an argument
	receiverUses map[string][]*ir.Call // value ID -> call sites invoking a method on it
	callByResult map[string]*ir.Call   // result value ID -> producing call
	returns      map[string][]string   // function ID -> returned value IDs
	queue        []string
}

type seed struct {
	label      string
	entryPoint string
	method     string
	path       string
	// anchored is true when entryPoint names an ENUMERATED entry point rather than
	// just the function the source was found in (ADR-009).
	anchored bool
	// unresolvedInputs names inputs injected into the entry point whose meaning the
	// frontend could not determine. A judgement that turns on what the handler was
	// given cannot be made over an input nobody could read.
	unresolvedInputs []string
	loc              ir.Loc
	// identityInjected records whether the framework handed this entry point the
	// caller's identity as a parameter. A reported fact, never a gate.
	identityInjected bool
}

// Analyze runs source-to-sink taint propagation over a lowered program.
//
// v0 is context-insensitive: a function's parameter carries the union of taint from
// all of its call sites. This can merge a tainted call site with a safe one. It is
// the standard starting point and is corrected by call-site cloning later; until
// then it can only over-report, never under-report.
func Analyze(d *ir.IR, m model.Model) Result {
	if missing := m.TaintFlowReq.Missing(d.Frontend.Capabilities); len(missing) > 0 {
		return Result{Applicable: false, MissingCapabilities: missing}
	}

	ix := ir.NewIndex(d)
	res := Result{Applicable: true}

	// Each class propagates independently. Sharing state would let an untrusted value
	// satisfy a sensitive-data policy and vice versa. Collection happens afterwards,
	// because some judgements are RELATIONAL — whether a record access was checked
	// against the caller's identity cannot be answered from one class alone.
	engines := make(map[string]*engine, len(m.Classifications))
	order := make([]string, 0, len(m.Classifications))

	for _, class := range m.Classifications {
		e := &engine{
			ix:           ix,
			m:            m,
			class:        class,
			tainted:      make(map[string]bool),
			pred:         make(map[string]edge),
			seeds:        make(map[string]seed),
			skipped:      make(map[string][]string),
			saidUnjudged: make(map[string]bool),
			argUses:      make(map[string][]*ir.Call),
			receiverUses: make(map[string][]*ir.Call),
			callByResult: make(map[string]*ir.Call),
			returns:      make(map[string][]string),
		}
		e.programInjects = programInjectsIdentity(ix)
		e.build()
		e.seedSources()
		e.propagate()
		engines[class.Class] = e
		order = append(order, class.Class)
	}

	seen := map[string]bool{}
	for _, class := range order {
		e := engines[class]
		res.Findings = append(res.Findings, e.collect(engines, d.Frontend.Capabilities)...)
		res.NoCallerIdentity = append(res.NoCallerIdentity, e.unjudgedIdentity...)
		res.Unjudged = append(res.Unjudged, e.unjudged...)
		for id, missing := range e.skipped {
			if !seen[id] {
				seen[id] = true
				res.Skipped = append(res.Skipped, SkippedPolicy{PolicyID: id, Missing: missing})
			}
		}
	}
	sort.Slice(res.Skipped, func(i, j int) bool { return res.Skipped[i].PolicyID < res.Skipped[j].PolicyID })

	sortFindings(res.Findings)
	return res
}

func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].SinkLoc.File != f[j].SinkLoc.File {
			return f[i].SinkLoc.File < f[j].SinkLoc.File
		}
		if f[i].SinkLoc.Line != f[j].SinkLoc.Line {
			return f[i].SinkLoc.Line < f[j].SinkLoc.Line
		}
		return f[i].SourceLoc.Line < f[j].SourceLoc.Line
	})
}

func (e *engine) build() {
	for _, fn := range e.ix.IR.Functions {
		e.returns[fn.ID] = fn.Returns
		for _, c := range fn.Calls {
			for _, a := range c.Args {
				if a.ValueID != "" {
					e.argUses[a.ValueID] = append(e.argUses[a.ValueID], c)
				}
			}
			if c.ReceiverID != "" {
				e.receiverUses[c.ReceiverID] = append(e.receiverUses[c.ReceiverID], c)
			}
			if c.ResultID != "" {
				e.callByResult[c.ResultID] = c
			}
		}
	}
}

// seedSources marks the origins this flow cares about. Which strategy a rule uses is
// explicit, so adding an origin is a data change rather than an engine change.
func (e *engine) seedSources() {
	for _, rule := range e.class.Rules {
		switch rule.Match {
		case model.MatchValueKind:
			e.seedByValueKind(rule)
		case model.MatchGlobalProperty:
			e.seedByGlobalProperty(rule)
		default:
			e.seedByEntryParamProperty(rule)
		}
	}
}

// seedByValueKind marks every value the frontend lowered with a given kind, e.g. the
// binding of a catch clause.
func (e *engine) seedByValueKind(rule model.SourceRule) {
	for _, fn := range e.ix.IR.Functions {
		for _, v := range fn.Values {
			if string(v.Kind) != rule.ValueKind {
				continue
			}
			label := v.Name
			if label == "" {
				label = rule.ValueKind
			}
			entry, anchored := enclosingEntry(e.ix, fn)
			sd := seed{label: label, entryPoint: entry, anchored: anchored}
			if ep, ok := entryOf(e.ix, fn); ok {
				sd.unresolvedInputs, sd.loc = ep.UnresolvedParams, ep.Loc
				sd.identityInjected = injectsIdentity(e.ix, ep)
			}
			e.seeds[v.ID] = sd
			if ep, ok := e.ix.EntryByFunc[fn.ID]; ok {
				sd := e.seeds[v.ID]
				sd.method, sd.path = ep.Detail["method"], ep.Detail["path"]
				e.seeds[v.ID] = sd
			}
			e.markTainted(v.ID, edge{
				desc:       fmt.Sprintf("source: %s (%s)", label, e.class.Label),
				loc:        v.Loc,
				resolution: ir.Resolved,
			})
		}
	}
}

// seedByGlobalProperty marks property accesses on a framework-bound global, which is
// how frameworks that do not pass a request object into the handler expose one.
func (e *engine) seedByGlobalProperty(rule model.SourceRule) {
	for _, fn := range e.ix.IR.Functions {
		for _, v := range fn.Values {
			if v.Kind != ir.ValueProperty || !matchesPath(v.Path, rule.Paths) {
				continue
			}
			base := e.ix.ValueByID[v.Base]
			if base == nil || base.Kind != "global" || base.Name != rule.Symbol {
				continue
			}
			label := fmt.Sprintf("%s.%s", rule.Symbol, v.Path)
			entry, anchored := enclosingEntry(e.ix, fn)
			sd := seed{label: label, entryPoint: entry, anchored: anchored}
			if ep, ok := entryOf(e.ix, fn); ok {
				sd.unresolvedInputs, sd.loc = ep.UnresolvedParams, ep.Loc
				sd.identityInjected = injectsIdentity(e.ix, ep)
			}
			e.seeds[v.ID] = sd
			if ep, ok := e.ix.EntryByFunc[fn.ID]; ok {
				sd := e.seeds[v.ID]
				sd.method, sd.path = ep.Detail["method"], ep.Detail["path"]
				e.seeds[v.ID] = sd
			}
			e.markTainted(v.ID, edge{
				desc:       fmt.Sprintf("source: %s (%s)", label, e.class.Label),
				loc:        v.Loc,
				resolution: ir.Resolved,
			})
		}
	}
}

func (e *engine) seedByEntryParamProperty(rule model.SourceRule) {
	for _, ep := range e.ix.IR.EntryPoints {
		fn := e.ix.FuncByID[ep.FunctionID]
		if fn == nil {
			continue
		}
		{
			if rule.EntryKind != ep.Kind {
				continue
			}
			if rule.Framework != "" && ep.Framework != "" && rule.Framework != ep.Framework {
				continue
			}
			param, ok := paramAt(fn, rule.ParamIndex)
			if !ok {
				continue
			}
			for _, v := range fn.Values {
				if v.Kind != ir.ValueProperty || v.Base != param.ValueID {
					continue
				}
				if !matchesPath(v.Path, rule.Paths) {
					continue
				}
				label := fmt.Sprintf("%s.%s", param.Name, v.Path)
				e.seeds[v.ID] = seed{
					label:      label,
					entryPoint: describeEntry(ep),
					method:     ep.Detail["method"],
					path:       ep.Detail["path"],
					// This rule iterates enumerated entry points, so anything it
					// seeds is anchored by construction.
					anchored:         true,
					unresolvedInputs: ep.UnresolvedParams,
					loc:              ep.Loc,
					identityInjected: injectsIdentity(e.ix, &ep),
				}
				e.markTainted(v.ID, edge{
					desc:       fmt.Sprintf("source: %s (%s)", label, e.class.Label),
					loc:        v.Loc,
					resolution: ir.Resolved,
				})
			}
		}
	}
}

func (e *engine) propagate() {
	for len(e.queue) > 0 {
		id := e.queue[0]
		e.queue = e.queue[1:]

		for _, f := range e.ix.FlowsFrom[id] {
			e.markTainted(f.To, edge{
				from:       id,
				kind:       f.Kind,
				desc:       e.describeFlow(f),
				loc:        f.Loc,
				resolution: ir.Resolved,
			})
		}

		for _, c := range e.argUses[id] {
			e.throughCall(id, c)
		}

		for _, c := range e.receiverUses[id] {
			e.throughReceiver(id, c)
		}

		if fn := e.ix.OwnerOfValue[id]; fn != nil && contains(e.returns[fn.ID], id) {
			for _, site := range e.ix.CallSitesOf[fn.ID] {
				if site.ResultID == "" {
					continue
				}
				e.markTainted(site.ResultID, edge{
					from:       id,
					desc:       fmt.Sprintf("returned from %s()", fn.Name),
					loc:        site.Loc,
					resolution: site.Callee.Resolution,
				})
			}
		}
	}
}

// throughCall propagates taint from a tainted argument into a call site: into the
// callee's parameter when the target is known, or into the result when it is not.
func (e *engine) throughCall(argValueID string, c *ir.Call) {
	for _, a := range c.Args {
		if a.ValueID != argValueID {
			continue
		}
		switch c.Callee.Kind {
		case "local":
			callee := e.ix.FuncByID[c.Callee.FunctionID]
			if callee == nil {
				continue
			}
			param, ok := paramAt(callee, a.Index)
			if !ok {
				continue
			}
			e.markTainted(param.ValueID, edge{
				from:       argValueID,
				desc:       fmt.Sprintf("passed as argument %d to %s()", a.Index, callee.Name),
				loc:        c.Loc,
				resolution: c.Callee.Resolution,
			})
		default:
			// External or unresolved: taint the result. Whether a traversed
			// sanitizer actually helps is decided at the sink, where the required
			// context is known.
			if c.ResultID == "" {
				continue
			}
			e.markTainted(c.ResultID, edge{
				from:       argValueID,
				desc:       fmt.Sprintf("through %s()", displaySymbol(c.Callee)),
				loc:        c.Loc,
				symbol:     c.Callee.Symbol,
				resolution: c.Callee.Resolution,
			})
		}
	}
}

// throughReceiver propagates taint from the object a method was called on: into the
// result (`s.trim()` keeps the taint) and, for higher-order methods, into the
// callback's parameter (`arr.forEach(h => ...)`, `p.then(v => ...)`).
func (e *engine) throughReceiver(receiverID string, c *ir.Call) {
	if rule, ok := e.m.CallbackFor(c.Method); ok {
		if arg, found := argAt(c, rule.CallbackArg); found && arg.FunctionID != "" {
			if callback := e.ix.FuncByID[arg.FunctionID]; callback != nil {
				if param, ok := paramAt(callback, rule.CallbackParam); ok {
					e.markTainted(param.ValueID, edge{
						from:       receiverID,
						desc:       fmt.Sprintf("into the %s() callback as `%s` (%s)", c.Method, param.Name, rule.Note),
						loc:        c.Loc,
						resolution: c.Callee.Resolution,
					})
				}
			}
		}
	}

	// A method on tainted data generally returns tainted data. Only external
	// receivers are handled here; a local callee's return is already propagated
	// through its own return values.
	if c.Callee.Kind == "local" || c.ResultID == "" {
		return
	}
	e.markTainted(c.ResultID, edge{
		from:       receiverID,
		desc:       fmt.Sprintf("through .%s() on tainted data", c.Method),
		loc:        c.Loc,
		symbol:     c.Callee.Symbol,
		resolution: c.Callee.Resolution,
	})
}

// collect walks every sink call site and reports those reached by tainted data.
// hasSeeds reports whether this class was observed anywhere in the program. A class
// with no seeds is one this engine has no vocabulary for in this codebase.
func (e *engine) hasSeeds() bool { return len(e.seeds) > 0 }

func (e *engine) collect(all map[string]*engine, caps ir.Capabilities) []Finding {
	var out []Finding
	for _, fn := range e.ix.IR.Functions {
		for _, c := range fn.Calls {
			for _, ch := range e.m.ChannelsMatching(c.Callee.Symbol, c.Method) {
				// A method-name channel only counts when its receiver really is the
				// object it describes. Without this, `.json()` on any value in the
				// program would be an HTTP response.
				if ch.ReceiverIsEntryParam >= 0 && e.receiverRootParam(c) != ch.ReceiverIsEntryParam {
					continue
				}
				if ch.Symbol != "" && c.Callee.Kind != "external" {
					continue
				}
				// The language's own containers are not stores of shared records.
				// Only a positive answer disqualifies: a frontend that cannot type
				// its receivers leaves this empty, and empty is not "not builtin".
				if ch.RequiresExternalReceiver && c.ReceiverTypeOrigin == "builtin" {
					continue
				}
				// Reaching a channel is not itself a defect. Policy decides whether
				// THIS class reaching THIS channel is forbidden (ADR-012).
				policies := e.m.PoliciesFor(e.class.Class, ch)
				if len(policies) == 0 {
					continue
				}
				for _, idx := range ch.ArgIndex {
					arg, ok := argAt(c, idx)
					if !ok || !e.tainted[arg.ValueID] {
						continue
					}
					for _, p := range policies {
						if missing := p.Requires.Missing(caps); len(missing) > 0 {
							e.skipped[p.ID] = missing
							continue
						}
						if p.RequiresRelationTo != "" {
							other := all[p.RequiresRelationTo]

							// A policy satisfiable ONLY by relating to another class
							// cannot be evaluated where that class is not observable.
							//
							// `unowned-record-access` is satisfied by relating a
							// selector to the caller's identity. Identity is seeded
							// from framework-specific shapes — `req.user` on Express,
							// `g.user` on Flask — and a framework with no such rule
							// yields no identity anywhere in the program. The policy
							// then cannot be satisfied by any code, however careful,
							// and reports every record access as unowned. That is a
							// statement about this engine's vocabulary, not about the
							// application (ADR-003).
							//
							// The test is empirical and program-wide: did anything at
							// all seed this class? Program-wide is what keeps it sound.
							// Asking per-flow would silence the primary defect, because
							// a handler with no ownership check contains no identity by
							// definition — an earlier version made exactly that mistake
							// and the express-idor corpus caught it.
							// An entry point given an input the frontend could not
							// read cannot support the conclusion that identity was
							// never consulted — the unread input may be exactly that.
							// Per entry point, not program-wide: the rest of the
							// application is still judged normally.
							if sd := e.seeds[e.originOf(arg.ValueID)]; len(sd.unresolvedInputs) > 0 {
								// One statement per entry point, not per flow: a
								// handler with six queries has one reason.
								key := p.ID + "\x00" + sd.entryPoint
								if !e.saidUnjudged[key] {
									e.saidUnjudged[key] = true
									e.unjudged = append(e.unjudged, Unjudged{
										PolicyID:   p.ID,
										EntryPoint: sd.entryPoint,
										Loc:        sd.loc,
										Reason: "an input injected here could not be resolved (" +
											strings.Join(sd.unresolvedInputs, ", ") +
											"); whatever defines it is not in the scanned tree",
									})
								}
								continue
							}
							if other == nil || !other.hasSeeds() {
								e.skipped[p.ID] = []string{
									"no source for " + p.RequiresRelationTo + " in this program",
								}
								continue
							}

							// A selection CONSTRAINED by the caller's identity is
							// scoped: `{where: {id, userId: user.id}}` cannot reach a
							// record the caller does not own, and no comparison appears
							// anywhere. This is how multi-tenant code is normally
							// written — the query carries the tenant rather than the
							// handler checking it — and a policy that only recognizes a
							// check calls every one of those a missing ownership check.
							//
							// Whether the constraint is expressed as a test before the
							// operation or as part of the selection is a matter of
							// style, not of security, so both satisfy the policy.
							//
							// The identity need not sit inside the selector. Passing it
							// alongside — `webhookService.delete(id, workspace.id)` —
							// is the same statement made with two arguments instead of
							// one nested object, and the operation is equally unable to
							// reach a record the caller does not own.
							//
							// Known looseness: the relation is "reached the same
							// operation", so identity carried as payload rather than as
							// scope — `update(id, {updatedBy: user.id})` — counts as if
							// it constrained the selection. Narrowing that needs
							// per-field tracking at the selector, which the IR does not
							// carry today.
							if e.operationCarries(c, other) {
								continue
							}

							// The guard may live anywhere the data travelled, not
							// only in the function holding the operation. Real code
							// checks in the caller and operates in a private helper.
							chain := e.functionsOnPath(arg.ValueID, fn)

							// NOTE: an earlier version skipped the judgement when no
							// actor identity appeared on the path, reasoning that you
							// cannot compare against something absent. That silences
							// the primary case — a handler with NO ownership check has
							// no actor identity in it, which is exactly what makes it
							// a defect. Distinguishing a login endpoint from an
							// unauthenticated data endpoint is not derivable from
							// code, so it belongs in declared policy (ADR-011).
							if effectivelyRelated(chain, c, other) {
								continue
							}
						}
						if f, reported := e.buildFinding(c, ch, p, arg); reported {
							// A judgement about the caller's identity, on an entry point
							// the framework handed no identity, is not a judgement. It
							// is the policy restating that it had nothing to compare
							// against, and it is right every time and useful never.
							//
							// Not a guess. 42 of these were adjudicated by hand against
							// the source of sixteen production repositories and the
							// precision was 0.00: twenty-four false, eighteen disputed,
							// nothing true. They were login endpoints, OAuth callbacks,
							// invite redemptions and webhooks, plus one lookup whose own
							// source comments that it is deliberately unscoped because
							// the caller was already authorized by signature.
							//
							// Reported, never counted as a finding, never gating -- the
							// same treatment as a flow that cannot be tied to the
							// enumerated surface. Frameworks that expose identity on a
							// request object are untouched, because there the absence of
							// an identity parameter says nothing at all.
							if f.EntryHasNoInjectedIdentity {
								e.unjudgedIdentity = append(e.unjudgedIdentity, f)
								continue
							}
							out = append(out, f)
						}
					}
				}
			}
		}
	}
	sortFindings(out)
	return out
}

// operationCarries reports whether the operation itself was handed data of the other
// class — in any argument or as its receiver.
func (e *engine) operationCarries(c *ir.Call, other *engine) bool {
	if other == nil {
		return false
	}
	if c.ReceiverID != "" && other.tainted[c.ReceiverID] {
		return true
	}
	for _, a := range c.Args {
		if a.ValueID != "" && other.tainted[a.ValueID] {
			return true
		}
	}
	return false
}

// effectivelyRelated reports whether a function relates data of another class to the
// operation in a way that actually governs it.
//
// A comparison counts only when it is a GUARD: a branch from which control can leave
// the handler early. `if (owner !== caller) { res.status(403); return; }` decides
// whether the handler continues; `if (owner !== caller) { log(); }` decides nothing,
// and the two are indistinguishable by position alone.
//
// A call carrying the other class is accepted without that test: an assertion helper
// enforces by throwing, which is a different shape. That is a known looseness — a
// helper that merely records is treated as enforcing.
func effectivelyRelated(chain []*ir.Function, op *ir.Call, other *engine) bool {
	if other == nil || len(chain) == 0 {
		return false
	}

	// The two clauses have different soundness, so they get different scope.
	//
	// A comparison guard may live anywhere on the path: a caller that returns early
	// genuinely prevents the callee from running, so verifying it by control flow is
	// sound across functions.
	//
	// "a call carrying actor identity is presumed to enforce" is only a heuristic —
	// an assertion helper enforces by throwing, but a recorder does not. Spanning the
	// whole call chain with it cleared real defects, so it stays confined to the
	// function performing the operation.
	if sink := chain[0]; sink != nil {
		for _, c := range sink.Calls {
			if c.ID == op.ID {
				continue
			}
			for _, a := range c.Args {
				if a.ValueID != "" && other.tainted[a.ValueID] {
					return true
				}
			}
		}
	}

	for _, fn := range chain {
		var gates []string
		for _, cmp := range fn.Comparisons {
			if cmp.Block == "" {
				continue
			}
			if other.tainted[cmp.Left] || other.tainted[cmp.Right] {
				gates = append(gates, cmp.Block)
			}
		}
		if len(gates) == 0 {
			continue
		}
		if g := cfg.Build(fn); g != nil && g.AnyGuard(gates) {
			return true
		}
	}
	return false
}

// functionsOnPath returns every function this flow actually passed through, derived
// from the evidence chain rather than from the whole call graph. Using the real path
// keeps a guard in one caller from excusing an unguarded call from somewhere else.
func (e *engine) functionsOnPath(valueID string, sink *ir.Function) []*ir.Function {
	seen := map[string]bool{}
	var out []*ir.Function

	add := func(fn *ir.Function) {
		if fn != nil && !seen[fn.ID] {
			seen[fn.ID] = true
			out = append(out, fn)
		}
	}
	add(sink)

	cur := valueID
	for hops := 0; cur != "" && hops < 256; hops++ {
		add(e.ix.OwnerOfValue[cur])
		ed, ok := e.pred[cur]
		if !ok {
			break
		}
		cur = ed.from
	}
	return out
}

// receiverRootParam follows a method call's receiver back through any intermediate
// method calls (`res.status(500).json(x)`) and reports which entry-point parameter it
// originates from, or -1.
func (e *engine) receiverRootParam(c *ir.Call) int {
	id := c.ReceiverID
	for hops := 0; hops < 8 && id != ""; hops++ {
		v := e.ix.ValueByID[id]
		if v == nil {
			return -1
		}
		switch v.Kind {
		case ir.ValueParam:
			fn := e.ix.OwnerOfValue[id]
			if fn == nil {
				return -1
			}
			if _, isEntry := e.ix.EntryByFunc[fn.ID]; !isEntry {
				return -1
			}
			for _, p := range fn.Params {
				if p.ValueID == id {
					return p.Index
				}
			}
			return -1
		case ir.ValueCallResult:
			prev := e.callByResult[id]
			if prev == nil {
				return -1
			}
			id = prev.ReceiverID
		default:
			return -1
		}
	}
	return -1
}

// enclosingEntry names the entry point a function belongs to, when it is one.
// injectsIdentity reports whether an entry point was handed the caller's identity as a
// parameter, and whether the program uses that mechanism at all.
//
// The second half is what makes the first half mean anything. On a framework that exposes
// identity on a request object, `req.user` is available whether or not a handler reads it,
// so a handler without it has said nothing. On a framework that INJECTS identity, a
// handler without an identity parameter genuinely was not handed one — the absence is a
// fact about the endpoint rather than about the code that happens to be written in it.
func injectsIdentity(ix *ir.Index, ep *ir.EntryPoint) bool {
	fn := ix.FuncByID[ep.FunctionID]
	if fn == nil {
		return false
	}
	for _, p := range fn.Params {
		if v := ix.ValueByID[p.ValueID]; v != nil && v.Kind == "actor-identity-param" {
			return true
		}
	}
	return false
}

// programInjectsIdentity reports whether ANY entry point in the program is handed the
// caller's identity as a parameter.
func programInjectsIdentity(ix *ir.Index) bool {
	for i := range ix.IR.EntryPoints {
		if injectsIdentity(ix, &ix.IR.EntryPoints[i]) {
			return true
		}
	}
	return false
}

// entryOf finds the enumerated entry point this function serves, following the call
// graph upward when the function is not itself a handler.
//
// A framework exposes untrusted input in more than one place: a handler parameter, but
// also a request global any helper can read. Requiring the source to sit IN a handler
// would lose the second shape entirely, so reachability is the test — is there an
// enumerated entry point from which this function is called?
func entryOf(ix *ir.Index, fn *ir.Function) (*ir.EntryPoint, bool) {
	if ep, ok := ix.EntryByFunc[fn.ID]; ok {
		return ep, true
	}

	seen := map[string]bool{fn.ID: true}
	queue := []string{fn.ID}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, site := range ix.CallSitesOf[id] {
			caller := ix.OwnerOfCall[site.ID]
			if caller == nil || seen[caller.ID] {
				continue
			}
			seen[caller.ID] = true
			if ep, ok := ix.EntryByFunc[caller.ID]; ok {
				return ep, true
			}
			queue = append(queue, caller.ID)
		}
	}
	return nil, false
}

// enclosingEntry names the entry point a flow belongs to. The second result reports
// whether that name is an ENUMERATED entry point or merely the function the source was
// found in.
//
// The distinction is the whole of ADR-009. A framework model that recognizes a
// parameter decorator but not the routing decorator around it — the two are separate
// detections, and another framework may borrow one vocabulary without the other — will
// happily seed sources in methods that were never enumerated as routes. Those flows may
// be real, but they are not assertions about an attack surface this engine mapped, and
// reporting them as though they were makes the surface look complete when it is not.
func enclosingEntry(ix *ir.Index, fn *ir.Function) (string, bool) {
	if ep, ok := entryOf(ix, fn); ok {
		return describeEntry(*ep), true
	}
	return fn.Name + "()", false
}

// buildFinding reconstructs the evidence path and decides whether the flow survives
// the sanitizers it actually passed through. Reported=false means taint was cleared.
func (e *engine) buildFinding(c *ir.Call, ch model.Channel, p model.Policy, arg ir.Arg) (Finding, bool) {
	path, origin := e.tracePath(arg.ValueID)

	var sanitizers []Sanitizer
	for _, h := range path {
		if h.Symbol == "" {
			continue
		}
		s, ok := e.m.SanitizerFor(h.Symbol)
		if !ok {
			continue
		}
		clears := s.Clears(ch.Context)
		sanitizers = append(sanitizers, Sanitizer{
			Symbol:   s.Symbol,
			Loc:      h.Loc,
			Clears:   clears,
			Note:     s.Note,
			Required: ch.Context,
		})
		if clears {
			return Finding{}, false
		}
	}

	sinkHop := Hop{
		Loc:         c.Loc,
		Description: fmt.Sprintf("reaches %s() argument %d", sinkName(c), arg.Index),
		Resolution:  c.Callee.Resolution,
	}
	path = append(path, sinkHop)

	// The channel names the weakness when it determines it; otherwise the policy does.
	cwe := p.CWE
	if ch.CWE != "" {
		cwe = ch.CWE
	}

	// A statement-building channel requires the untrusted value to have been BUILT into
	// a statement: concatenated, or interpolated into a template. Passing a value along
	// whole is passing data, not composing a program.
	//
	// This is what separates SQL injection from the method name it shares with everything
	// else. `execute` is a database call on a cursor and a use-case invocation in a CQRS
	// application, and no amount of looking at the name will tell them apart: one
	// production codebase produced 495 findings on `usecase.execute(command)` alone. The
	// command is an object that was constructed, never text that was composed, so the
	// question "was this built into a statement" answers it and the question "what is
	// this method called" never could.
	//
	// The cost is stated rather than hidden: a handler that passes an entire caller-
	// supplied string as the whole query is not composition and is not reported here.
	if ch.RequiresComposition && !composedIntoText(path) {
		return Finding{}, false
	}
	// A destination is chosen, not built. Untrusted data composed into it usually leaves
	// the caller a path segment rather than a machine to point at.
	if ch.RequiresWholeValue && composedIntoText(path) {
		return Finding{}, false
	}

	// A channel that needs to know what its receiver is, matched by a frontend that
	// could not say, is a weaker claim than the path resolution alone suggests. It is
	// still reported — the operation may well be a record selector — but it has not
	// earned the confidence that stops a build (ADR-005).
	confidence := confidenceOf(path)
	if ch.RequiresExternalReceiver && c.ReceiverTypeOrigin == "" && confidence == High {
		confidence = Medium
	}

	sd := e.seeds[origin]
	return Finding{
		Analysis:      p.ID,
		DataClass:     e.class.Class,
		ChannelID:     ch.ID,
		Visibility:    ch.Visibility,
		Class:         p.Finding,
		CWE:           cwe,
		Message:       p.Reason,
		Confidence:    confidenceOf(path),
		SourceLoc:     e.locOf(origin),
		SourceLabel:   sd.label,
		EntryPoint:    sd.entryPoint,
		EntryMethod:   sd.method,
		EntryPath:     sd.path,
		EntryAnchored: sd.anchored,
		EntryHasNoInjectedIdentity: sd.anchored && !sd.identityInjected && e.programInjects &&
			p.RequiresRelationTo == e.m.IdentityClass(),
		SinkLoc:      c.Loc,
		SinkSymbol:   sinkName(c),
		SinkArgIndex: arg.Index,
		SinkContext:  ch.Context,
		SinkRational: ch.Rationale,
		Path:         path,
		Sanitizers:   sanitizers,
	}, true
}

// originOf returns the seed a tainted value came from.
func (e *engine) originOf(id string) string {
	seen := map[string]bool{}
	for id != "" && !seen[id] {
		seen[id] = true
		if _, ok := e.seeds[id]; ok {
			return id
		}
		id = e.pred[id].from
	}
	return ""
}

// tracePath walks predecessors back to the seed and returns the path in source order.
func (e *engine) tracePath(valueID string) ([]Hop, string) {
	var reversed []Hop
	cur := valueID
	origin := valueID
	seen := make(map[string]bool)

	for cur != "" && !seen[cur] {
		seen[cur] = true
		ed, ok := e.pred[cur]
		if !ok {
			break
		}
		reversed = append(reversed, Hop{
			Loc:         ed.loc,
			Description: ed.desc,
			Symbol:      ed.symbol,
			Kind:        ed.kind,
			Resolution:  ed.resolution,
		})
		origin = cur
		cur = ed.from
	}

	path := make([]Hop, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		path = append(path, reversed[i])
	}
	return path, origin
}

func (e *engine) markTainted(id string, ed edge) {
	if id == "" || e.tainted[id] {
		return
	}
	e.tainted[id] = true
	e.pred[id] = ed
	e.queue = append(e.queue, id)
}

func (e *engine) describeFlow(f ir.Flow) string {
	target := e.ix.ValueByID[f.To]
	name := ""
	if target != nil {
		name = target.Name
	}
	switch f.Kind {
	case "assign":
		if name != "" {
			return fmt.Sprintf("assigned to `%s`", name)
		}
		return "assigned"
	case "template":
		return "interpolated into a template literal"
	case "binary":
		return "concatenated"
	case "property":
		if target != nil && target.Path != "" {
			return fmt.Sprintf("property `%s`", target.Path)
		}
		return "property access"
	case "return":
		return "returned"
	default:
		return f.Kind
	}
}

func (e *engine) locOf(valueID string) ir.Loc {
	if v := e.ix.ValueByID[valueID]; v != nil {
		return v.Loc
	}
	return ir.Loc{}
}

func confidenceOf(path []Hop) Confidence {
	worst := High
	for _, h := range path {
		switch h.Resolution {
		case ir.DynamicUnresolved:
			return Low
		case ir.Probable:
			worst = Medium
		}
	}
	return worst
}

func sinkFunctionName(ix *ir.Index, c *ir.Call) string {
	if fn := ix.OwnerOfCall[c.ID]; fn != nil {
		return fn.Name
	}
	return ""
}

// Touches reports whether any file this finding depends on is in the given set.
//
// The whole evidence path counts, not just the sink. A change to a helper can introduce
// a defect whose dangerous operation sits in a file the change never opened, and scoping
// to the sink alone would hide exactly the flows that a review most needs to see: the
// ones where the damage happens somewhere the author was not looking.
func (f Finding) Touches(files map[string]bool) bool {
	if files[f.SinkLoc.File] || files[f.SourceLoc.File] {
		return true
	}
	for _, h := range f.Path {
		if files[h.Loc.File] {
			return true
		}
	}
	return false
}

// Fingerprint is a finding's identity across runs.
//
// Deliberately built from what the finding IS and not from where it currently sits: the
// judgement, the entry point it belongs to, the file and function holding the operation,
// the symbol reached, and what the data was. A line number is absent on purpose —
// inserting an import above a defect must not turn it into a new defect, or a baseline
// is worthless on the first commit that touches the file.
//
// Two genuinely indistinguishable findings share a fingerprint. That is correct: for the
// question a baseline asks — is this one already known — they are the same finding.
func (f Finding) Fingerprint() string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		f.Analysis,
		f.CWE,
		f.EntryPoint,
		f.SinkLoc.File,
		f.SinkFunction,
		f.SinkSymbol,
		f.SourceLabel,
	}, "\x00")))
	return hex.EncodeToString(h[:8])
}

func describeEntry(ep ir.EntryPoint) string {
	parts := make([]string, 0, 3)
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

// sinkName is how a sink is identified in output: its resolved symbol when there is
// one, otherwise the method it was reached through.
func sinkName(c *ir.Call) string {
	if c.Callee.Symbol != "" {
		return c.Callee.Symbol
	}
	if c.Method != "" {
		return "." + c.Method
	}
	return "<unresolved>"
}

func displaySymbol(c ir.Callee) string {
	if c.Symbol != "" {
		return c.Symbol
	}
	return "<unresolved call>"
}

func matchesPath(path string, prefixes []string) bool {
	head, _, _ := strings.Cut(path, ".")
	for _, p := range prefixes {
		if head == p {
			return true
		}
	}
	return false
}

func paramAt(fn *ir.Function, index int) (ir.Param, bool) {
	for _, p := range fn.Params {
		if p.Index == index {
			return p, true
		}
	}
	return ir.Param{}, false
}

func argAt(c *ir.Call, index int) (ir.Arg, bool) {
	for _, a := range c.Args {
		if a.Index == index {
			return a, true
		}
	}
	return ir.Arg{}, false
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
