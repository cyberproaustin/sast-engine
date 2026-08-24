// Package report renders analysis results. Rendering never decides what is true —
// it only presents what the engine concluded, including what it declined to claim.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/assertion"

	"github.com/cyberproaustin/sast-engine/core/internal/expectation"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/ledger"
	"github.com/cyberproaustin/sast-engine/core/internal/scan"
	"github.com/cyberproaustin/sast-engine/core/internal/surface"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// Text writes a human-readable report.
func Text(w io.Writer, res scan.Result) error {
	b := &strings.Builder{}

	d := res.IR
	fmt.Fprintf(b, "frontend: %s %s  (IR %s)\n", d.Frontend.Name, d.Frontend.Version, d.IRVersion)
	fmt.Fprintf(b, "capabilities: %s\n", describeCapabilities(d.Frontend.Capabilities))
	writeResolutionQuality(b, d)

	writeSurface(b, res.Surface)
	writeBaselineState(b, res)
	writeScopeState(b, res)
	writeExemptions(b, res.Exempted)
	newness, scoped := map[string]bool{}, map[string]bool{}
	for _, f := range res.Taint.Findings {
		newness[f.Fingerprint()] = res.IsNew(f)
		scoped[f.Fingerprint()] = res.InScope(f)
	}
	writeTaint(b, res.Taint, newness, scoped)
	writeExpectations(b, res.Expectation)
	writeCoverage(b, assertion.Evaluate(res))

	_, err := io.WriteString(w, b.String())
	return err
}

// The enumerated surface is reported whether or not anything was found. An operator
// who cannot recognize their own application here should not trust any conclusion
// drawn from it (ADR-009).
func writeSurface(b *strings.Builder, s surface.Surface) {
	groups := s.Groups()
	names := s.GroupNames()

	fmt.Fprintf(b, "\nsurface: %d entry point(s) in %d group(s)\n", len(s.Entries), len(names))
	writeCompleteness(b, s)
	if len(s.Entries) == 0 {
		return
	}

	for _, name := range names {
		fmt.Fprintf(b, "  %s\n", name)
		for _, e := range groups[name] {
			fmt.Fprintf(b, "    %-30s %s\n", e.Label(), describeControls(e))
		}
	}
	writeUniversalControls(b, s)
	writeUnresolvedInputs(b, s)
}

// Controls applied to every entry point, named once rather than repeated on each.
//
// This is the population answering a question the name cannot (ADR-010). On real code
// every control reads "unclassified", because nothing distinguishes an authentication
// guard from a rate limiter by name alone; what CAN be observed is that one of them is
// on all 39 routes and the other on 10. The first tells a reader nothing about any
// particular route, and reporting that is more honest than leaving them to assume it is
// protection.
func writeUniversalControls(b *strings.Builder, s surface.Surface) {
	if len(s.Entries) < 2 {
		return
	}
	seen := map[string]bool{}
	var universal []surface.Control
	for _, e := range s.Entries {
		for _, c := range e.Controls {
			if !c.Discriminates && !seen[c.Ref] {
				seen[c.Ref] = true
				universal = append(universal, c)
			}
		}
	}
	if len(universal) == 0 {
		return
	}
	sort.Slice(universal, func(i, j int) bool { return universal[i].Name < universal[j].Name })

	fmt.Fprintf(b, "\n  applied to every entry point: %d control(s)\n", len(universal))
	fmt.Fprintf(b, "    these distinguish nothing between routes; they are cross-cutting, not per-route protection\n")
	for _, c := range universal {
		fmt.Fprintf(b, "    %-30s on all %d\n", c.Name, c.Reach)
	}
}

// Aggregated, never per entry point. One decorator applied across three hundred routes
// is one fact about the scan and three hundred lines of symptom, and the operator needs
// the fact: whatever defines this is not in the tree you pointed at.
func writeUnresolvedInputs(b *strings.Builder, s surface.Surface) {
	byName := map[string]int{}
	for _, e := range s.Entries {
		for _, name := range e.EntryPoint.UnresolvedParams {
			byName[name]++
		}
	}
	if len(byName) == 0 {
		return
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return byName[names[i]] > byName[names[j]] })

	fmt.Fprintf(b, "\n  inputs of unknown meaning: %d\n", len(byName))
	fmt.Fprintf(b, "    injected into handlers, defined outside the scanned tree — widen the root to resolve\n")
	for _, name := range names {
		fmt.Fprintf(b, "    %-30s on %d entry point(s)\n", name, byName[name])
	}
}

// The most dangerous report this engine can produce is a thin surface, because it looks
// exactly like a clean application. This is the one place that difference can be stated.
func writeCompleteness(b *strings.Builder, s surface.Surface) {
	c := s.Completeness
	if !c.Suspect(len(s.Entries)) {
		if len(s.Entries) == 0 {
			fmt.Fprintf(b, "  none enumerated - no analysis below can mean anything\n")
		}
		return
	}

	if len(s.Entries) == 0 {
		fmt.Fprintf(b, "  INCOMPLETE: none enumerated, but %d function(s) read caller-supplied input\n", c.InputFunctions)
	} else {
		fmt.Fprintf(b, "  INCOMPLETE: %d function(s) read caller-supplied input and no enumerated\n", c.UnreachedInputFunctions)
		fmt.Fprintf(b, "  entry point reaches them (%d read it in total)\n", c.InputFunctions)
	}
	fmt.Fprintf(b, "  This application routes requests in a way the framework models do not\n")
	fmt.Fprintf(b, "  recognize. Findings below cover only what was enumerated; silence here is\n")
	fmt.Fprintf(b, "  the model failing to see the application, not the application being clean.\n")
}

// Coverage against the whole published catalog, not against the part we cover.
//
// A tool that lists its own rules and calls that a coverage map is telling you how much of
// itself it implements. The denominator here is every weakness a rule could be written
// for -- static-analysis-detectable, not deprecated, has a code shape, in a language this
// engine can parse -- and it is derived from MITRE's release rather than chosen by us.
func writeCatalogCoverage(b *strings.Builder) {
	asserted, total := ledger.Covered()
	counts := ledger.Counts(ledger.All())
	fmt.Fprintf(b, "\ncatalog: %s\n", ledger.Edition())
	fmt.Fprintf(b, "  asserts %d of %d weaknesses a rule could be written for (%.1f%%)\n",
		asserted, total, 100*float64(asserted)/float64(total))
	fmt.Fprintf(b, "  of the full catalog: %d abstract, %d undecidable by static analysis,\n",
		counts[ledger.Abstract], counts[ledger.Undecidable])
	fmt.Fprintf(b, "  %d out of scope for these languages, %d decidable and not built\n",
		counts[ledger.OutOfScope], counts[ledger.NotBuilt])

	// The catalog carries its own priority list, so what matters most is read from MITRE
	// rather than argued about here. Counted against the members a rule could be written
	// for: several are C memory-safety weaknesses no frontend here will ever parse, and
	// counting those as gaps would make the number meaningless in the flattering
	// direction as much as the unflattering one.
	if top, total := ledger.CoveredOnList(ledger.TopTwentyFive); total > 0 {
		fmt.Fprintf(b, "  of the CWE Top 25 that apply to these languages: %d of %d asserted\n", top, total)
		for _, e := range ledger.MissingFromList(ledger.TopTwentyFive) {
			fmt.Fprintf(b, "    not built: %-9s %s\n", e.ID, e.Name)
		}
	}
}

func describeControls(e surface.EntryFacts) string {
	if len(e.Controls) == 0 {
		return "controls: none"
	}
	parts := make([]string, 0, len(e.Controls))
	for _, c := range e.Controls {
		kind := c.Kind
		if kind == "" {
			kind = "unclassified"
		}
		// A control every entry point carries distinguishes none of them, and saying so
		// beside each one keeps a reader from counting it as protection specific to this
		// route (ADR-010).
		if !c.Discriminates {
			kind += ",universal"
		}
		parts = append(parts, fmt.Sprintf("%s[%s,%s]", c.Name, kind, c.Scope))
	}
	return "controls: " + strings.Join(parts, " ")
}

// The baseline's effect is stated before any finding, because "3 findings" means two
// different things depending on whether a baseline was in play, and a reader who does
// not know which is looking at a number they cannot interpret.
func writeBaselineState(b *strings.Builder, res scan.Result) {
	if res.Baseline == nil {
		fmt.Fprintf(b, "\nbaseline: none supplied — every finding below is reported as new\n")
		return
	}
	fmt.Fprintf(b, "\nbaseline: %d finding(s) previously recorded\n", res.Baseline.Count())
	fmt.Fprintf(b, "  a recorded finding is still reported and still counted; it does not gate\n")
}

// Scoping changes which findings can stop a build, and a reader who does not know a
// scope was applied will read "0 gating" as "nothing wrong here".
func writeScopeState(b *strings.Builder, res scan.Result) {
	if res.Changed == nil {
		return
	}
	fmt.Fprintf(b, "\nscope: %d changed file(s) - only findings touching them can gate\n", len(res.Changed))
	fmt.Fprintf(b, "  everything else is still analyzed and still reported\n")
}

// A declaration's effect on findings is reported, never silent (ADR-013).
func writeExemptions(b *strings.Builder, ex []scan.Exemption) {
	if len(ex) == 0 {
		return
	}
	fmt.Fprintf(b, "\ndeclared exemptions: %d judgement(s) do not apply\n", len(ex))
	for _, e := range ex {
		fmt.Fprintf(b, "  %s at %s (%s): declared %s by %q — %s\n",
			e.PolicyID, e.EntryPoint, e.Loc, e.Property, e.DeclaredBy, e.Reason)
	}
}

func writeTaint(b *strings.Builder, res taint.Result, newness, scoped map[string]bool) {
	if !res.Applicable {
		writeNotApplicable(b, "taint-flow", res.MissingCapabilities)
		return
	}
	// Findings are grouped by the flow that produced them, so a reader can tell
	// which question was being asked.
	byFlow := map[string][]taint.Finding{}
	var order []string
	// Findings the engine could not tie to an enumerated entry point are separated,
	// not mixed in. Presenting them alongside anchored findings would claim a surface
	// the engine did not map (ADR-009).
	var unanchored []taint.Finding
	for _, f := range res.Findings {
		if !f.EntryAnchored {
			unanchored = append(unanchored, f)
			continue
		}
		if _, seen := byFlow[f.Analysis]; !seen {
			order = append(order, f.Analysis)
		}
		byFlow[f.Analysis] = append(byFlow[f.Analysis], f)
	}
	sort.Strings(order)

	fmt.Fprintf(b, "\nanalyses: ran\n")
	// A judgement the engine declined to make is stated. Silence here would be
	// indistinguishable from a clean result (ADR-003).
	for _, u := range res.Unjudged {
		fmt.Fprintf(b, "  CANNOT JUDGE %s at %s (%s): %s\n",
			u.PolicyID, u.EntryPoint, u.Loc, u.Reason)
	}
	// A policy that never ran is not a policy that passed. Until now this was visible
	// only as a "not evaluated" row further down the coverage table, which is easy to
	// read as a detail about the table rather than about this scan (ADR-003).
	for _, sk := range res.Skipped {
		fmt.Fprintf(b, "  NOT EVALUATED %s: %s\n", sk.PolicyID, strings.Join(sk.Missing, ", "))
	}
	if len(res.Findings) == 0 {
		fmt.Fprintf(b, "  no findings\n")
		return
	}

	anchored, gating, known, out := 0, 0, 0, 0
	for _, flow := range order {
		fmt.Fprintf(b, "\n  -- %s --\n", flow)
		for _, f := range byFlow[flow] {
			isNew := newness == nil || newness[f.Fingerprint()]
			inScope := scoped == nil || scoped[f.Fingerprint()]
			writeTaintFinding(b, f)
			if !isNew {
				fmt.Fprintf(b, "  in baseline: %s\n", f.Fingerprint())
				known++
			}
			if !inScope {
				fmt.Fprintf(b, "  outside this change\n")
				out++
			}
			if f.InTestModule {
				fmt.Fprintf(b, "  in a test module: ships with the repository, does not run in production\n")
			}
			if f.DependsOnUse {
				fmt.Fprintf(b, "  whether this is a defect depends on what the result is used for,\n")
				fmt.Fprintf(b, "  which this analysis cannot see: reported, never gating\n")
			}
			anchored++
			if isNew && inScope && !f.DependsOnUse && f.Confidence.Gating() {
				gating++
			}
		}
	}
	switch {
	case known > 0 && out > 0:
		fmt.Fprintf(b, "\n  %d finding(s), %d new, %d in this change, %d gating\n", anchored, anchored-known, anchored-out, gating)
	case known > 0:
		fmt.Fprintf(b, "\n  %d finding(s), %d new, %d gating\n", anchored, anchored-known, gating)
	case out > 0:
		fmt.Fprintf(b, "\n  %d finding(s), %d in this change, %d gating\n", anchored, anchored-out, gating)
	default:
		fmt.Fprintf(b, "\n  %d finding(s), %d gating\n", anchored, gating)
	}
	writeUnanchored(b, unanchored)
	writeNoCallerIdentity(b, res)
}

// Findings on entry points the framework handed no caller identity, named once as a
// group rather than read one at a time.
//
// These are login flows, OAuth callbacks, invite redemptions and webhooks: endpoints whose
// job is to ESTABLISH identity, or which are authenticated by a token or a signature
// instead of a session. Across sixteen production repositories they were 29 of the 42
// ownership findings, and read individually they look like 29 unrelated problems.
//
// The engine does not decide anything from this. "The handler never consults who the
// caller is" remains literally true of a login endpoint, and whether that is by design is
// a claim about the application that belongs in a declaration (ADR-011). What is reported
// here is only the fact the engine can observe -- identity is injected in this program,
// and it was not injected here -- which is enough for an operator to recognize the whole
// group at once and declare it, or to notice that one of them does not belong.
func writeNoCallerIdentity(b *strings.Builder, res taint.Result) {
	group := res.NoCallerIdentity
	if len(group) == 0 {
		return
	}

	byEntry := map[string]int{}
	var order []string
	for _, f := range group {
		if _, seen := byEntry[f.EntryPoint]; !seen {
			order = append(order, f.EntryPoint)
		}
		byEntry[f.EntryPoint]++
	}
	sort.Slice(order, func(i, j int) bool { return byEntry[order[i]] > byEntry[order[j]] })

	fmt.Fprintf(b, "\nnot judged: %d flow(s) on %d entry point(s) the framework handed no caller identity\n",
		len(group), len(order))
	fmt.Fprintf(b, "  identity is injected elsewhere in this program but not here, which is what login,\n")
	fmt.Fprintf(b, "  OAuth callback, invite and webhook endpoints look like. Hand-adjudicated against\n")
	fmt.Fprintf(b, "  sixteen production repositories, 42 of these were 0.00 precision, so they are\n  reported and not counted. Declare establishesIdentity where it is by design.\n")
	for _, e := range order {
		fmt.Fprintf(b, "    %-56s %d\n", e, byEntry[e])
	}
}

// A flow that reaches a dangerous destination but cannot be traced back to any entry
// point this engine enumerated is real information and is reported as such — but it is
// not a statement about the attack surface, so it is kept out of the count that is and
// never gates. Usually it means a framework was only partly recognized: input was
// identified, the route around it was not.
func writeUnanchored(b *strings.Builder, findings []taint.Finding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintf(b, "\nnot anchored to the enumerated surface: %d flow(s)\n", len(findings))
	fmt.Fprintf(b, "  reported, never gating — the engine could not connect these to an entry point it enumerated\n")
	for _, f := range findings {
		fmt.Fprintf(b, "    %s (%s) in %s\n      %s reaches %s at %s\n",
			f.Class, f.CWE, f.EntryPoint, f.SourceLabel, f.SinkSymbol, f.SinkLoc)
	}
}

func writeExpectations(b *strings.Builder, res expectation.Result) {
	if !res.Applicable {
		writeNotApplicable(b, "expectations", res.MissingCapabilities)
		return
	}

	fmt.Fprintf(b, "\nanalysis expectations: ran\n")
	if res.PolicyPresent {
		fmt.Fprintf(b, "  declared: %s\n", res.PolicyPath)
	} else {
		// Not the same as an empty policy: nothing has been stated, so nothing
		// beyond inference can be enforced (ADR-011).
		fmt.Fprintf(b, "  declared: none supplied — only inferred expectations are available, and those never gate\n")
	}
	fmt.Fprintf(b, "  inferred: from peers (>=%d peers, >=%.0f%% conformance)\n",
		res.Thresholds.MinPeers, res.Thresholds.MinRatio*100)

	// A declaration that matched nothing is a stated expectation that was never
	// checked. Silence here would read as compliance.
	for _, u := range res.UnmatchedRules {
		fmt.Fprintf(b, "  UNCHECKED declaration %q matched no entry point (%s)\n", u.Match, u.Reason)
	}
	// A declaration's effect is visible, never silent.
	for _, sup := range res.Suppressed {
		fmt.Fprintf(b, "  suppressed on %s: %s — declared %q (%s)\n",
			sup.EntryPoint, sup.Missing, sup.DeclaredBy, sup.Reason)
	}

	if len(res.Findings) == 0 {
		fmt.Fprintf(b, "  no unmet expectations\n")
		return
	}
	for _, f := range res.Findings {
		writeExpectationFinding(b, f)
	}

	gating := 0
	for _, f := range res.Findings {
		if f.Gates {
			gating++
		}
	}
	fmt.Fprintf(b, "\n  %d unmet expectation(s), %d gating (only declared expectations gate)\n",
		len(res.Findings), gating)
}

func writeNotApplicable(b *strings.Builder, analysis string, missing []string) {
	fmt.Fprintf(b, "\nanalysis %s: NOT APPLICABLE\n", analysis)
	fmt.Fprintf(b, "  frontend does not declare: %s\n", strings.Join(missing, ", "))
	fmt.Fprintf(b, "  this is not a clean result — the analysis did not run\n")
}

func writeTaintFinding(b *strings.Builder, f taint.Finding) {
	fmt.Fprintf(b, "\n[%s] %s (%s)\n", strings.ToUpper(string(f.Confidence)), f.Class, f.CWE)
	fmt.Fprintf(b, "  %s\n", f.Message)
	fmt.Fprintf(b, "  entry: %s\n", f.EntryPoint)
	fmt.Fprintf(b, "  sink:  %s argument %d at %s\n", f.SinkSymbol, f.SinkArgIndex, f.SinkLoc)
	if f.SinkRational != "" {
		fmt.Fprintf(b, "         %s\n", f.SinkRational)
	}

	fmt.Fprintf(b, "  flow:\n")
	for i, h := range f.Path {
		marker := ""
		if h.Resolution != "" && h.Resolution != ir.Resolved {
			marker = fmt.Sprintf("  <%s>", h.Resolution)
		}
		fmt.Fprintf(b, "    %d. %-28s %s%s\n", i+1, h.Loc.String(), h.Description, marker)
	}

	fmt.Fprintf(b, "  sanitizers considered: ")
	if len(f.Sanitizers) == 0 {
		fmt.Fprintf(b, "none on this path\n")
		return
	}
	fmt.Fprintln(b)
	for _, s := range f.Sanitizers {
		verdict := "INSUFFICIENT"
		if s.Clears {
			verdict = "clears"
		}
		fmt.Fprintf(b, "    - %s at %s: %s for context %q\n", s.Symbol, s.Loc, verdict, s.Required)
		if s.Note != "" {
			fmt.Fprintf(b, "      %s\n", s.Note)
		}
	}
}

func writeExpectationFinding(b *strings.Builder, f expectation.Finding) {
	tier := "advisory"
	if f.Gates {
		tier = "GATING"
	}
	fmt.Fprintf(b, "\n[%s] %s (%s)  <%s expectation>\n", tier, f.Class, f.CWE, f.Origin)
	fmt.Fprintf(b, "  %s\n", f.Message)
	fmt.Fprintf(b, "  entry: %s at %s\n", f.EntryPoint, f.EntryLoc)
	fmt.Fprintf(b, "  group: %s\n", f.Group)

	switch f.Origin {
	case expectation.OriginDeclared:
		fmt.Fprintf(b, "  declared by: %s\n", f.DeclaredBy)
		fmt.Fprintf(b, "  reason:      %s\n", f.DeclaredReason)
	default:
		fmt.Fprintf(b, "  evidence: %d of %d comparable entry points apply %s\n",
			f.Conforming, f.Peers, f.MissingName)
		for _, peer := range f.ConformingList {
			fmt.Fprintf(b, "    - %s\n", peer)
		}
	}
}

// The coverage map is the answer to "what does this tool claim about this codebase,
// and what does it decline to claim?" (ADR-007). It lists requirements the tool cannot
// check on purpose: a map showing only successes is marketing.
func writeCoverage(b *strings.Builder, rep assertion.Report) {
	counts := rep.Counts()
	writeCatalogCoverage(b)
	fmt.Fprintf(b, "\ncoverage (%s requirements this build knows about)\n", assertion.ASVSEdition)
	fmt.Fprintf(b, "  %s\n", assertion.CatalogScope)
	fmt.Fprintf(b, "  %d violated, %d satisfied, %d not evaluated, %d out of reach for static analysis, %d not built\n",
		counts[assertion.Violated], counts[assertion.Satisfied],
		counts[assertion.NotEvaluated], counts[assertion.OutOfReach], counts[assertion.NotBuilt])

	for _, e := range rep.Requirements {
		marker := map[assertion.State]string{
			assertion.Violated:     "VIOLATED",
			assertion.Satisfied:    "ok",
			assertion.NotEvaluated: "NOT EVALUATED",
			assertion.OutOfReach:   "out of reach",
			assertion.NotBuilt:     "not built",
		}[e.State]

		detail := ""
		if e.Findings > 0 {
			detail = fmt.Sprintf(" (%d finding(s))", e.Findings)
		}
		fmt.Fprintf(b, "  %-14s %-8s %s%s\n", marker, e.Requirement.ID, e.Requirement.Title, detail)
		if e.Reason != "" {
			fmt.Fprintf(b, "                          %s\n", e.Reason)
		}
	}

	if len(rep.Rollup) == 0 && len(rep.Unmapped) == 0 {
		return
	}
	// Derived from the CWE of each finding, never authored on a rule (ADR-007).
	fmt.Fprintf(b, "\n  %s rollup (derived from CWE):\n", assertion.Top10Edition)
	for _, r := range rep.Rollup {
		fmt.Fprintf(b, "    %-34s %d finding(s)  [%s]\n", r.Category, r.Findings, strings.Join(r.CWEs, " "))
	}
	for _, cwe := range rep.Unmapped {
		fmt.Fprintf(b, "    %-34s unmapped — not guessed into a category\n", cwe)
	}
}

// What a frontend CAN do and how much of it actually worked on this tree are different
// questions, and only the first is a capability. A checkout without its dependencies
// installed types almost nothing — the frontend is working exactly as designed and the
// answers are still weak — and a reader who sees `typeChecker=true` above a thin report
// has no way to tell that from a codebase with nothing in it.
//
// Derived from the IR rather than declared, because it is a property of this run.
func writeResolutionQuality(b *strings.Builder, d *ir.IR) {
	if !d.Frontend.Capabilities.TypeChecker {
		return
	}

	typed, total := 0, 0
	for _, fn := range d.Functions {
		for _, c := range fn.Calls {
			if c.Method == "" {
				continue
			}
			total++
			if c.ReceiverType != "" {
				typed++
			}
		}
	}
	if total == 0 {
		return
	}

	pct := 100 * float64(typed) / float64(total)
	fmt.Fprintf(b, "type resolution: %d of %d method receivers typed (%.0f%%)\n", typed, total, pct)
	// Measured across sixteen production repositories scanned without their
	// dependencies installed, this sits between 8% and 59%. Below the low end, the
	// frontend is answering "I don't know" to most of what it is asked.
	if pct < 25 {
		fmt.Fprintf(b, "  low — most receivers could not be typed, commonly because dependency types\n")
		fmt.Fprintf(b, "  are not installed. Judgements that turn on what a receiver IS cannot be made\n")
		fmt.Fprintf(b, "  here and are reported below the gate, not omitted.\n")
	}
}

func describeCapabilities(c ir.Capabilities) string {
	parts := []string{
		fmt.Sprintf("typeChecker=%t", c.TypeChecker),
		fmt.Sprintf("interprocedural=%t", c.Interprocedural),
		fmt.Sprintf("crossModule=%t", c.CrossModule),
	}
	if len(c.FrameworkModels) > 0 {
		parts = append(parts, "models="+strings.Join(c.FrameworkModels, "+"))
	}
	return strings.Join(parts, " ")
}
