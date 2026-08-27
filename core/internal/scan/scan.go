// Package scan runs the analyses over a lowered program and returns everything a
// report needs.
//
// The surface comes first and is returned whether or not any analysis produced a
// finding (ADR-009): what the engine understood about the application is part of the
// result, not scaffolding discarded on the way to a finding list.
package scan

import (
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/baseline"
	"github.com/cyberproaustin/sast-engine/core/internal/callshape"
	"github.com/cyberproaustin/sast-engine/core/internal/decision"
	"github.com/cyberproaustin/sast-engine/core/internal/expectation"
	"github.com/cyberproaustin/sast-engine/core/internal/flow"
	"github.com/cyberproaustin/sast-engine/core/internal/guard"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/literal"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/policy"
	"github.com/cyberproaustin/sast-engine/core/internal/scope"
	"github.com/cyberproaustin/sast-engine/core/internal/store"
	"github.com/cyberproaustin/sast-engine/core/internal/surface"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// Result is a complete scan.
type Result struct {
	IR          *ir.IR
	Surface     surface.Surface
	Taint       taint.Result
	Expectation expectation.Result
	// Exempted records judgements a declaration made inapplicable. A declaration's
	// effect is always visible (ADR-013).
	Exempted []Exemption
	// Baseline is the set of findings a previous run recorded, or nil when none was
	// supplied. Nil and empty mean different things: empty asserts the codebase was
	// clean when the file was written.
	Baseline *baseline.Baseline
	// Changed is the set of files this run is being asked about, or nil when the run is
	// about the whole tree. Scoping affects only what GATES: every finding is still
	// analyzed, reported and counted, because a flow that a change did not touch is
	// still a real flow and hiding it would make the report a function of the diff
	// rather than of the code.
	Changed map[string]bool
}

// InScope reports whether a finding is one this run is being asked about. With no
// change set, every finding is in scope.
func (r Result) InScope(f taint.Finding) bool {
	return r.Changed == nil || f.Touches(r.Changed)
}

// Gates reports whether this one finding should fail the run.
//
// The single definition. It was written out three times -- here, in the text report and in
// the SARIF writer -- and the copies drifted the moment a new reason not to gate was
// added, so a finding was excluded in the report and still failed the build.
//
// A finding gates only when all of it holds: the engine tied it to an entry point it
// enumerated (ADR-009), the call graph resolved well enough to be confident (ADR-005), the
// judgement did not turn on something the analysis cannot see, no baseline records it, and
// it touches the change under review.
func (r Result) Gates(f taint.Finding) bool {
	// The finding's own merits live on the finding, so that the SARIF level and this
	// gate cannot disagree about them; only the two questions about the RUN are asked
	// here.
	return f.Actionable() && r.IsNew(f) && r.InScope(f)
}

// IsNew reports whether a finding was absent from the baseline. With no baseline every
// finding is new, which is the correct reading of "nothing has been recorded yet".
func (r Result) IsNew(f taint.Finding) bool {
	return !r.Baseline.Known(f.Fingerprint())
}

// Exemption is a finding a declared property removed, and why.
type Exemption struct {
	PolicyID   string
	EntryPoint string
	Loc        ir.Loc
	Property   string
	DeclaredBy string
	Reason     string
}

// Run enumerates the surface and runs every analysis over it. The policy may be nil,
// which means the team has declared nothing — a state the report names explicitly
// rather than treating as an empty ruleset.
func Run(d *ir.IR, m model.Model, p *policy.Policy) Result {
	// The views come first, because a template sink is IR and everything below reads
	// IR. A server-rendered application decides its escaping in a file the language's
	// compiler never saw, and joining that file to the values a handler passed is a
	// program-wide question no single call site can answer (flow.JoinViews).
	flow.JoinViews(d)

	s := surface.Build(d, m, p)
	t := taint.Analyze(d, m)
	// Dataflow reaches the same operation through syntactically different branches in
	// real applications. Across the measured batch this made one error-message exposure
	// in uptime-kuma count three times solely because sendHttpError selects three status
	// codes. Consolidate before declarations and reporting so every downstream count is a
	// count of weaknesses, while RelatedSites retains each branch and its evidence path.
	t.Findings = collapseFlowFindings(d, t.Findings)
	exempted := applyDeclarations(&t, m, p)

	// Weaknesses visible in a call's own arguments, with no dataflow involved. Appended
	// to the same finding list because they are the same kind of claim to a reader, even
	// though the analysis that produced them is a different one.
	t.Findings = append(t.Findings, callshape.Analyze(d, m)...)
	t.Findings = append(t.Findings, decision.Analyze(d, m, t.ByClass)...)
	t.Findings = append(t.Findings, store.Analyze(d, m, t.ByClass)...)
	t.Findings = append(t.Findings, literal.Analyze(d, m)...)
	t.Findings = append(t.Findings, guard.Analyze(d, m)...)
	t.Findings = append(t.Findings, scope.Analyze(d, m, t.ByClass)...)
	ix := ir.NewIndex(d)
	authenticated := authenticatedEntries(s)
	for i := range t.Findings {
		t.Findings[i].Provenance = ix.ProvenanceOf(t.Findings[i].SinkLoc)
		t.Findings[i].EntryAuthenticates = authenticated[t.Findings[i].EntryPoint]
	}
	unanchorUnreachedModules(ix, d, t.Findings)
	t.Findings = collapseIdenticalFindings(t.Findings)

	return Result{
		IR:          d,
		Surface:     s,
		Taint:       t,
		Expectation: expectation.Analyze(d, s, m, p, expectation.DefaultThresholds()),
		Exempted:    exempted,
	}
}

// authenticatedEntries maps the label a finding records for its entry point onto whether
// that entry point authenticates its caller.
//
// The surface decides the fact (surface.EntryFacts.Authenticates) and this only carries
// it to the findings, so there is one answer and not two -- the same reason Gates is
// defined once. The join is a string because that is what a finding records: it names its
// entry point rather than pointing at one.
//
// Both spellings are keyed because two exist. The dataflow analysis writes the framework
// alongside the route ("GET /links [express]"), which is what a reader needs and what the
// fingerprint has always contained; the analyses that judge a call rather than a flow
// write the route alone. Keying both is honest about that; teaching one of them to lie
// about its own labels to make a lookup work would not be.
func authenticatedEntries(s surface.Surface) map[string]bool {
	out := map[string]bool{}
	for _, e := range s.Entries {
		if !e.Authenticates {
			continue
		}
		out[taint.EntryLabel(e.EntryPoint)] = true
		out[e.Label()] = true
	}
	return out
}

// unanchorUnreachedModules withdraws the anchoring claim from a finding written in a
// module nothing in the program names.
//
// Anchored means the engine tied this to the surface it enumerated (ADR-009), and it is
// what decides whether a finding fails a build. Several kinds assert it by construction,
// on the sound reasoning that a weak hash in a file nothing routes to is still a weak
// hash -- but "nothing routes to it" and "nothing can run it" are different facts, and
// the second one was never asked. An application's settings button had its `window.open`
// reported at error level on the strength of a handler local to the component, and the
// component is not imported, re-exported or dynamically loaded anywhere in its own
// repository: there is no path from any enumerated entry point down to that line.
//
// The finding is not withdrawn, because the code says what it says. What is withdrawn is
// the claim about WHERE it is, which is the claim the engine could not support -- the
// same correction the surface already made when it started printing `<unresolved:expr>`
// for a mount path it could not read instead of `*`.
//
// A module that declares an entry point of its own is exempt whatever the import graph
// says: the framework reaches those by path, and a finding inside a route this run
// enumerated is anchored to that route by definition. Silence here would be the surface
// and the findings contradicting each other.
func unanchorUnreachedModules(ix *ir.Index, d *ir.IR, findings []taint.Finding) {
	unreferenced := make(map[string]bool)
	for _, m := range d.Modules {
		if m.Unreferenced {
			unreferenced[m.Path] = true
		}
	}
	if len(unreferenced) == 0 {
		return
	}
	for _, ep := range d.EntryPoints {
		if fn := ix.FuncByID[ep.FunctionID]; fn != nil {
			delete(unreferenced, fn.Module)
		}
	}
	for i := range findings {
		if unreferenced[findings[i].SinkLoc.File] {
			findings[i].EntryAnchored = false
		}
	}
}

// collapseFlowFindings identifies a flow by its rule, the function holding the sink and
// the value's semantic origin. Locations are deliberately absent: ADR-014 requires the
// same weakness to survive reformatting. Entry point and files remain in the key because
// two equal parameter names in unrelated request paths are not evidence of one value.
//
// This is separate from Finding.Fingerprint on purpose. Batch 1 has 131 adjudications
// keyed by that stable value; re-keying them to make a presentation decision would orphan
// the ledger. It is also limited to dataflow findings. A call-shape rule can use the same
// symbol several times for genuinely different written values -- the three juice-shop
// directory listings are the measured counterexample.
func collapseFlowFindings(d *ir.IR, all []taint.Finding) []taint.Finding {
	type key struct {
		analysis, cwe, entryPoint       string
		channel, sinkFile, sinkFunction string
		sinkOperation                   string
		sourceFile, sourceLabel, class  string
		valuePath                       string
	}

	ix := ir.NewIndex(d)
	rank := map[taint.Confidence]int{taint.Low: 0, taint.Medium: 1, taint.High: 2}
	best := make(map[key]int, len(all))
	out := make([]taint.Finding, 0, len(all))
	for _, f := range all {
		k := key{
			analysis: f.Analysis, cwe: f.CWE, entryPoint: f.EntryPoint,
			channel: f.ChannelID, sinkFile: f.SinkLoc.File, sinkFunction: ownerOfSink(ix, f),
			sinkOperation: sinkOperation(f.SinkSymbol),
			sourceFile:    f.SourceLoc.File, sourceLabel: f.SourceLabel, class: f.DataClass,
			valuePath: valuePath(f.Path),
		}
		at, seen := best[k]
		if !seen {
			best[k] = len(out)
			out = append(out, f)
			continue
		}

		if rank[f.Confidence] > rank[out[at].Confidence] {
			previous := siteOf(out[at])
			related := append([]taint.Site{previous}, out[at].RelatedSites...)
			f.RelatedSites = append(related, f.RelatedSites...)
			out[at] = f
			continue
		}
		out[at].RelatedSites = append(out[at].RelatedSites, siteOf(f))
		out[at].RelatedSites = append(out[at].RelatedSites, f.RelatedSites...)
	}
	return out
}

func siteOf(f taint.Finding) taint.Site {
	loc := f.SinkLoc
	// For an object response the tainted field is the syntactic site a reviewer needs.
	// The frontend records that initializer on the enclosure hop; the last hop remains
	// the encompassing call because it is still the sink.
	if len(f.Path) > 1 {
		h := f.Path[len(f.Path)-2]
		if h.Kind == "enclose" && h.Loc.File == f.SinkLoc.File {
			loc = h.Loc
		}
	}
	return taint.Site{Loc: loc, Path: f.Path}
}

// valuePath distinguishes two values derived from the same root without smuggling a
// source position back into the key. linkwarden derives both a Content-Type and a download
// filename from one token and sends both as headers; those are two judgements. The three
// uptime-kuma branches carry the same msg through the same enclosure and differ only in
// the final status-selecting sink hop, which is intentionally omitted here.
func valuePath(path []taint.Hop) string {
	var b strings.Builder
	for i, h := range path {
		if i == len(path)-1 {
			break
		}
		b.WriteString(h.Kind)
		b.WriteByte(0)
		b.WriteString(h.Symbol)
		b.WriteByte(0)
		b.WriteString(h.Description)
		b.WriteByte(0)
	}
	return b.String()
}

// sinkOperation keeps distinct dangerous operations in one function distinct while
// treating receiver chains that only select a branch-local option as the same sink.
// uptime-kuma spells the three occurrences res.status(503|404|403).json; the called
// operation is json in all three. subprocess.call and subprocess.Popen remain separate.
func sinkOperation(symbol string) string {
	if at := strings.LastIndexByte(symbol, '.'); at >= 0 {
		return symbol[at+1:]
	}
	return symbol
}

func ownerOfSink(ix *ir.Index, f taint.Finding) string {
	for _, c := range ix.CallByID {
		if c.Loc == f.SinkLoc {
			if fn := ix.OwnerOfCall[c.ID]; fn != nil {
				return fn.Name
			}
		}
	}
	return f.SinkFunction
}

// collapseIdenticalFindings keeps one of any set that say the same thing about the same
// line.
//
// A template rendered from two handlers reaches the same interpolation twice, and a reader
// looking at `views/search.ejs:3` reported twice learns nothing from the second one: same
// weakness, same line, same value, same judgement. Two findings at one line that differ in
// ANY of those are two findings and both survive -- `res.send(err.message)` is a
// disclosure and a scripting bug at once, and reporting one of them would be reporting
// half the problem.
//
// The one kept is the most confident, because confidence here is how well the call graph
// resolved (ADR-005) and the better-resolved path is the better evidence.
func collapseIdenticalFindings(all []taint.Finding) []taint.Finding {
	type key struct{ cwe, loc, source, analysis string }
	rank := map[taint.Confidence]int{taint.Low: 0, taint.Medium: 1, taint.High: 2}

	best := make(map[key]int, len(all))
	order := make([]int, 0, len(all))
	for i, f := range all {
		k := key{f.CWE, f.SinkLoc.String(), f.SourceLabel, f.Analysis}
		prev, seen := best[k]
		if !seen {
			best[k] = i
			order = append(order, i)
			continue
		}
		if rank[f.Confidence] > rank[all[prev].Confidence] {
			f.RelatedSites = append([]taint.Site{{Loc: all[prev].SinkLoc, Path: all[prev].Path}},
				all[prev].RelatedSites...)
			best[k] = i
			for j, at := range order {
				if at == prev {
					order[j] = i
					break
				}
			}
			all[i] = f
			continue
		}
		all[prev].RelatedSites = append(all[prev].RelatedSites, f.RelatedSites...)
	}

	out := make([]taint.Finding, 0, len(order))
	for _, i := range order {
		out = append(out, all[i])
	}
	return out
}

// applyDeclarations removes findings whose judgement a declared property makes
// inapplicable, and returns what it removed.
//
// The engine never learns what any particular declaration MEANS. A policy names the
// property that exempts it; the team states whether their endpoint has that property.
func applyDeclarations(t *taint.Result, m model.Model, p *policy.Policy) []Exemption {
	if p == nil || !p.Present || len(t.Findings) == 0 {
		return nil
	}

	exemptedBy := map[string]string{}
	for _, pol := range m.Policies {
		if pol.ExemptedBy != "" {
			exemptedBy[pol.ID] = pol.ExemptedBy
		}
	}
	if len(exemptedBy) == 0 {
		return nil
	}

	var kept []taint.Finding
	var out []Exemption

	for _, f := range t.Findings {
		property, governed := exemptedBy[f.Analysis]
		if !governed {
			kept = append(kept, f)
			continue
		}
		var matched *policy.EntryPointRule
		for _, rule := range p.RulesFor(f.EntryMethod, f.EntryPath, "") {
			if rule.Declares(property) {
				r := rule
				matched = &r
				break
			}
		}
		if matched == nil {
			kept = append(kept, f)
			continue
		}
		out = append(out, Exemption{
			PolicyID:   f.Analysis,
			EntryPoint: f.EntryPoint,
			Loc:        f.SinkLoc,
			Property:   property,
			DeclaredBy: matched.Match.String(),
			Reason:     matched.Reason,
		})
	}

	t.Findings = kept
	return out
}

// Gating reports whether the run should fail a pipeline.
//
// Two things gate, for two different reasons: a dataflow finding whose path fully
// resolved (confidence, never severity — ADR-005), and a violated expectation the team
// declared for itself (ADR-011). An inferred expectation never gates.
func (r Result) Gating() bool {
	for _, f := range r.Taint.Findings {
		// An unanchored finding never gates however well its path resolved. The
		// engine could not connect it to an entry point it enumerated, so it is not
		// an assertion over the surface (ADR-009) and must not stop a build.
		//
		// A baselined finding does not gate either. It is still reported and still
		// counted — the baseline records that a finding was already there, and makes
		// no claim that it is acceptable.
		if f.DependsOnUse != "" {
			continue
		}
		if f.EntryAnchored && f.Confidence.Gating() && r.IsNew(f) && r.InScope(f) {
			return true
		}
	}
	return r.Expectation.Gating()
}

// AnyFindings reports whether anything at all was reported.
func (r Result) AnyFindings() bool {
	return len(r.Taint.Findings) > 0 || len(r.Expectation.Findings) > 0
}

// NotApplicable reports whether any analysis could not run.
func (r Result) NotApplicable() bool {
	return !r.Taint.Applicable || !r.Expectation.Applicable
}
