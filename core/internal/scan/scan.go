// Package scan runs the analyses over a lowered program and returns everything a
// report needs.
//
// The surface comes first and is returned whether or not any analysis produced a
// finding (ADR-009): what the engine understood about the application is part of the
// result, not scaffolding discarded on the way to a finding list.
package scan

import (
	"github.com/cyberproaustin/sast-engine/core/internal/baseline"
	"github.com/cyberproaustin/sast-engine/core/internal/expectation"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/policy"
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
	s := surface.Build(d, m, p)
	t := taint.Analyze(d, m)
	exempted := applyDeclarations(&t, m, p)

	return Result{
		IR:          d,
		Surface:     s,
		Taint:       t,
		Expectation: expectation.Analyze(d, s, m, p, expectation.DefaultThresholds()),
		Exempted:    exempted,
	}
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
