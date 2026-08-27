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
	writeTaint(b, res.Taint, newness, scoped, res.Gates)
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
	writeClasses(b, s)
	writeCompleteness(b, s)
	if len(s.Entries) == 0 {
		writeNonApplicationSurface(b, s)
		return
	}

	// A surface is the primary output and an operator is meant to AUDIT it: if the
	// enumerated entry points do not match the application they know, no conclusion below
	// is worth anything (ADR-009). That argument assumes it can be read. One production
	// repository enumerates 280 routes, and printing every one put 320 lines between the
	// header and the first finding -- at which point nobody audits anything.
	//
	// So a large surface is summarised by group, with the count and how many carry no
	// control. Nothing is hidden: the groups are all there, the totals are exact, and the
	// SARIF output has always carried every entry point for anything that wants them.
	if len(s.Entries) > surfaceDetailLimit {
		fmt.Fprintf(b, "  listed by group; %d entry points is too many to read one by one\n", len(s.Entries))
		for _, name := range names {
			g := groups[name]
			bare := 0
			for _, e := range g {
				if len(e.Controls) == 0 {
					bare++
				}
			}
			fmt.Fprintf(b, "    %-52s %3d entry point(s), %d with no control\n", name, len(g), bare)
		}
	} else {
		for _, name := range names {
			fmt.Fprintf(b, "  %s\n", name)
			for _, e := range groups[name] {
				fmt.Fprintf(b, "    %-30s %s\n", e.Label(), describeControls(e))
			}
		}
	}
	writeUniversalControls(b, s)
	writeUnresolvedInputs(b, s)
	writeNonApplicationSurface(b, s)
}

// A route and a cron job are both entry points and they are not the same number.
//
// Printed whenever the surface holds more than one kind, because a single total that
// folds background work into a route count overstates what a caller can reach -- and the
// surface is meant to be AUDITED against the application an operator knows (ADR-009),
// which they cannot do if the classes are added together. Each line says who can reach
// that class, which is the fact that makes the split worth making.
func writeClasses(b *strings.Builder, s surface.Surface) {
	classes := s.Classes()
	if len(classes) < 2 {
		return
	}
	for _, c := range classes {
		fmt.Fprintf(b, "  %-16s %4d  reachable by: %s\n", c.Kind, c.Count, c.Trust)
	}
}

// Example and vendored registrations are kept visible without letting their presence
// make an empty application surface look partly enumerated. jupyterhub supplied the
// measured failure: all nine routes were examples, while none of the application was
// represented.
func writeNonApplicationSurface(b *strings.Builder, s surface.Surface) {
	if len(s.NonApplicationEntries) == 0 {
		return
	}
	counts := map[ir.Provenance]int{}
	for _, entry := range s.NonApplicationEntries {
		counts[entry.Provenance]++
	}
	fmt.Fprintf(b, "\nnon-application surface: %d entry point(s), excluded from the application count\n",
		len(s.NonApplicationEntries))
	for _, provenance := range []ir.Provenance{ir.Example, ir.Vendored} {
		if counts[provenance] == 0 {
			continue
		}
		fmt.Fprintf(b, "  %s: %d\n", provenance, counts[provenance])
		if len(s.NonApplicationEntries) > surfaceDetailLimit {
			continue
		}
		for _, entry := range s.NonApplicationEntries {
			if entry.Provenance == provenance {
				fmt.Fprintf(b, "    %-30s %s\n", entry.Label(), entry.Loc())
			}
		}
	}
}

// Controls applied to every entry point, named once rather than repeated on each.
//
// This is the population answering a question the name cannot (ADR-010). On real code
// every control reads "unclassified", because nothing distinguishes an authentication
// guard from a rate limiter by name alone; what CAN be observed is that one of them is
// on all 39 routes and the other on 10. The first tells a reader nothing about any
// particular route, and reporting that is more honest than leaving them to assume it is
// protection.
// sameRuleDetailLimit is how many findings from ONE rule are shown in full before the
// rest are counted by file. Gating findings are never subject to it.
const sameRuleDetailLimit = 5

// surfaceDetailLimit is where listing every entry point stops helping. Chosen so that the
// surface stays shorter than the findings it introduces on every repository in the corpus.
const surfaceDetailLimit = 40

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
	if !c.Suspect(s.RemoteEntries()) {
		if s.RemoteEntries() == 0 {
			fmt.Fprintf(b, "  nothing here answers a caller - no analysis below says what a stranger could do\n")
		}
		return
	}

	statedUnreachedCount := c.UnreachedShareSuspect(s.RemoteEntries())
	if statedUnreachedCount {
		if s.RemoteEntries() == 0 {
			// "None" means none a CALLER can reach. A program with sixteen process starts
			// and no route has no remote surface at all, and saying "none enumerated" beside
			// sixteen listed entry points would read as a contradiction rather than a fact.
			fmt.Fprintf(b, "  INCOMPLETE: no entry point a caller can reach, and %d function(s) read caller-supplied input\n", c.InputFunctions)
		} else {
			fmt.Fprintf(b, "  INCOMPLETE: %d function(s) read caller-supplied input and no enumerated\n", c.UnreachedInputFunctions)
			fmt.Fprintf(b, "  entry point reaches them (%d read it in total)\n", c.InputFunctions)
		}
	}
	writeUnenumeratedRoutes(b, c)
	fmt.Fprintf(b, "  This application routes requests in a way the framework models do not\n")
	fmt.Fprintf(b, "  recognize. Findings below cover only what was enumerated; silence here is\n")
	fmt.Fprintf(b, "  the model failing to see the application, not the application being clean.\n")
	// The unreached listing counts something, and the count is only on the line above
	// when the SHARE of unreachable input-reading code is what made this run suspect. A
	// run flagged for a missing route family instead would print "a further 4 ... are not
	// counted above" against nothing at all, and "them" would refer to nothing.
	if !statedUnreachedCount && c.UnreachedInputFunctions > 0 {
		fmt.Fprintf(b, "  separately, %d of the %d function(s) that read caller-supplied input are\n",
			c.UnreachedInputFunctions, c.InputFunctions)
		fmt.Fprintf(b, "  not reached from anything enumerated - too few to call the surface thin\n")
		fmt.Fprintf(b, "  on their own, and listed because the reason may be the same one\n")
	}
	writeUnreached(b, c)
}

// A route family missed WHOLE is the one incompleteness a reader cannot infer from any
// other number in this report, so it names the files rather than counting them: the claim
// is checkable in one `ls`, and an accusation nobody can check is one a reader skips.
func writeUnenumeratedRoutes(b *strings.Builder, c surface.Completeness) {
	if len(c.UnenumeratedRoutes) == 0 {
		return
	}
	byConvention := map[string][]surface.UnenumeratedRoute{}
	var order []string
	for _, r := range c.UnenumeratedRoutes {
		if _, seen := byConvention[r.Convention]; !seen {
			order = append(order, r.Convention)
		}
		byConvention[r.Convention] = append(byConvention[r.Convention], r)
	}
	sort.Strings(order)
	for _, convention := range order {
		rs := byConvention[convention]
		fmt.Fprintf(b, "  INCOMPLETE: %d file(s) the framework serves at an address of their own\n", len(rs))
		fmt.Fprintf(b, "  are not in the enumeration - %s\n", convention)
		for i, r := range rs {
			if i >= sampleRoutes {
				fmt.Fprintf(b, "    ... and %d more\n", len(rs)-sampleRoutes)
				break
			}
			fmt.Fprintf(b, "    %-58s %s\n", r.Module, r.Evidence)
		}
	}
}

// sampleRoutes bounds the listing above for the same reason the unreached listing is
// bounded: 37 lines of paths is a wall, and three is enough to check the claim.
const sampleRoutes = 3

// A count of unreachable code is an accusation against the enumeration, and an
// accusation nobody can check is one a reader learns to skip. This says which
// functions and why, bounded to a summary: three named examples and the directories
// they sit in, per cause.
func writeUnreached(b *strings.Builder, c surface.Completeness) {
	if c.NonProductionInputFunctions > 0 {
		fmt.Fprintf(b, "  a further %d read it in modules that cannot serve a request (tests,\n", c.NonProductionInputFunctions)
		fmt.Fprintf(b, "  examples, checked-in dependencies) and are not counted above\n")
	}
	if len(c.Unreached) == 0 {
		return
	}
	fmt.Fprintf(b, "  why the surface does not reach them:\n")
	for _, g := range c.Unreached {
		fmt.Fprintf(b, "    %d  %s\n", g.Count, g.Cause)
		if g.FromReachedCode > 0 {
			fmt.Fprintf(b, "       %d of those from code the surface does reach: the route was found,\n", g.FromReachedCode)
			fmt.Fprintf(b, "       the call was found, and the edge between them was not\n")
		}
		if len(g.Modules) > 0 {
			var parts []string
			for _, mod := range g.Modules {
				parts = append(parts, fmt.Sprintf("%s (%d)", mod.Dir, mod.Count))
			}
			fmt.Fprintf(b, "       in %s\n", strings.Join(parts, ", "))
		}
		for _, fn := range g.Sample {
			line := fmt.Sprintf("       %s at %s", fn.Name, fn.Loc)
			if fn.Detail != "" {
				line += "  [" + fn.Detail + "]"
			}
			fmt.Fprintf(b, "%s\n", line)
		}
	}
}

// Coverage against the whole published catalog, not against the part we cover.
//
// A tool that lists its own rules and calls that a coverage map is telling you how much of
// itself it implements. The denominator here is every weakness a rule could be written
// for -- static-analysis-detectable, not deprecated, has a code shape, in a language this
// engine can parse -- and it is derived from MITRE's release rather than chosen by us.
func writeCatalogCoverage(b *strings.Builder) {
	asserted, subsumed, total := ledger.Covered()
	counts := ledger.Counts(ledger.All())
	fmt.Fprintf(b, "\ncatalog: %s\n", ledger.Edition())
	fmt.Fprintf(b, "  asserts %d of %d weaknesses a rule could be written for (%.1f%%)\n",
		asserted, total, 100*float64(asserted)/float64(total))
	// Stated on its own line and never added to the one above. A weakness whose PARENT's
	// rule catches it is covered, and it is covered by somebody else's rule -- reporting
	// the two as one number would be the kind of arithmetic this whole ledger exists to
	// make impossible.
	if subsumed > 0 {
		fmt.Fprintf(b, "  and %d more are subsumed: a rule above them catches them, because\n", subsumed)
		fmt.Fprintf(b, "  what distinguishes them is a detail the analysis never looks at\n")
	}
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
		// Labelled by their actual state. "Not built" and "no analysis of source could
		// decide this" are different claims, and printing both as the former would put a
		// permanent item on a to-do list and make the gap look like laziness.
		for _, e := range ledger.MissingFromList(ledger.TopTwentyFive) {
			fmt.Fprintf(b, "    %-12s %-9s %s\n", e.Claim.State, e.ID, e.Name)
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

// gates is passed in rather than recomputed. There is one definition of what stops a
// build (scan.Gates) and this file used to hold a second, which had already drifted: it
// omitted the test-module term, so a hardcoded key in a spec file counted as gating here
// and did not in SARIF. Two answers to that question is one too many.
func writeTaint(b *strings.Builder, res taint.Result, newness, scoped map[string]bool, gates func(taint.Finding) bool) {
	if !res.Applicable {
		writeNotApplicable(b, "taint-flow", res.MissingCapabilities)
		return
	}
	// Findings are grouped by the flow that produced them, so a reader can tell
	// which question was being asked.
	byFlow := map[string][]taint.Finding{}
	var order []string
	var nonApplication []taint.Finding
	// Findings the engine could not tie to an enumerated entry point are separated,
	// not mixed in. Presenting them alongside anchored findings would claim a surface
	// the engine did not map (ADR-009).
	var unanchored []taint.Finding
	// And findings the context judgement enumerates rather than reports (policy.Context):
	// a key in a fixture, a path only an operator walks. The non-application section
	// below is the same separation drawn one step earlier, which is why provenance is
	// asked first -- "this is not our code" is a more specific answer than "this is not
	// reported", and the reader who has it does not need the weaker one.
	var notReported []taint.Finding
	for _, f := range res.Findings {
		if f.Provenance != "" {
			nonApplication = append(nonApplication, f)
			continue
		}
		if !f.Reportable() {
			notReported = append(notReported, f)
			continue
		}
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
		// One rule firing twenty-one times says the same thing twenty-one times, and in
		// one production repository that was 210 lines of identical hardcoded-secret
		// findings between the reader and the next rule. The first few are printed in
		// full and the rest are counted by file.
		//
		// A GATING finding is never summarised away, however many there are: those are
		// the ones that stop a build, and a reader who has to expand a summary to see
		// what stopped it is a reader who will turn the tool off. The count and the files
		// are exact either way, and SARIF carries every one regardless.
		shown := 0
		elided := map[string]int{}
		for _, f := range byFlow[flow] {
			isNew := newness == nil || newness[f.Fingerprint()]
			inScope := scoped == nil || scoped[f.Fingerprint()]
			stops := gates(f)
			if shown >= sameRuleDetailLimit && !stops {
				elided[f.SinkLoc.File]++
				anchored++
				if !isNew {
					known++
				}
				if !inScope {
					out++
				}
				continue
			}
			shown++
			writeTaintFinding(b, f)
			if !isNew {
				fmt.Fprintf(b, "  in baseline: %s\n", f.Fingerprint())
				known++
			}
			if !inScope {
				fmt.Fprintf(b, "  outside this change\n")
				out++
			}
			if f.DependsOnUse != "" {
				// Verdict first, reason after. A reader scanning for what will stop a
				// build should not have to finish a sentence to find out.
				for i, line := range wrap("reported, never gating: "+f.DependsOnUse, 74) {
					if i == 0 {
						fmt.Fprintf(b, "  %s\n", line)
						continue
					}
					fmt.Fprintf(b, "    %s\n", line)
				}
			}
			anchored++
			if stops {
				gating++
			}
		}
		if len(elided) > 0 {
			total := 0
			files := make([]string, 0, len(elided))
			for f, n := range elided {
				total += n
				files = append(files, f)
			}
			sort.Strings(files)
			fmt.Fprintf(b, "\n  and %d more from this rule, none of them gating:\n", total)
			for _, f := range files {
				fmt.Fprintf(b, "    %-64s %d\n", f, elided[f])
			}
		}
	}
	if anchored == 0 {
		fmt.Fprintf(b, "  no application findings\n")
	} else {
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
	}
	writeUnanchored(b, unanchored)
	writeNotReported(b, notReported, newness, scoped)
	writeNonApplicationFindings(b, nonApplication, newness, scoped)
	writeNoCallerIdentity(b, res)
}

// Findings the engine enumerated and does not report, each under the reason it is not
// reported.
//
// Separated, and never dropped. 12 of the 41 false positives from one batch's
// worst-scoring rules were a correct rule firing in a test fixture, an example, or a
// management command an operator runs, and reading those beside an application's own
// defects is what teaches a maintainer to stop reading the rule. Printing them in full is
// the same measurement read from the other side: operators paste values out of tickets,
// cron entries and CI variables into those arguments, and a key parked in a fixture is a
// real key. Both sentences are true, and a section that states which one applies is the
// only way to say both.
func writeNotReported(b *strings.Builder, findings []taint.Finding, newness, scoped map[string]bool) {
	if len(findings) == 0 {
		return
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if a, c := findings[i].NotReportedBecause(), findings[j].NotReportedBecause(); a != c {
			return a < c
		}
		if findings[i].Analysis != findings[j].Analysis {
			return findings[i].Analysis < findings[j].Analysis
		}
		return findings[i].SinkLoc.String() < findings[j].SinkLoc.String()
	})

	fmt.Fprintf(b, "\nenumerated, not reported: %d finding(s), each under the reason it is not\n",
		len(findings))
	reason, analysis, shown := "", "", 0
	elided := map[string]int{}
	flushElided := func() {
		if len(elided) == 0 {
			return
		}
		files := make([]string, 0, len(elided))
		for file := range elided {
			files = append(files, file)
		}
		sort.Strings(files)
		fmt.Fprintf(b, "\n  additional %s finding(s):\n", analysis)
		for _, file := range files {
			fmt.Fprintf(b, "    %-64s %d\n", file, elided[file])
		}
		elided = map[string]int{}
	}

	for _, f := range findings {
		if why := f.NotReportedBecause(); why != reason {
			flushElided()
			reason, analysis = why, ""
			fmt.Fprintf(b, "\n  -- %s --\n", reason)
		}
		if f.Analysis != analysis {
			flushElided()
			analysis, shown = f.Analysis, 0
			fmt.Fprintf(b, "\n  %s\n", analysis)
		}
		if shown >= sameRuleDetailLimit {
			elided[f.SinkLoc.File]++
			continue
		}
		shown++
		writeTaintFinding(b, f)
		if newness != nil && !newness[f.Fingerprint()] {
			fmt.Fprintf(b, "  in baseline: %s\n", f.Fingerprint())
		}
		if scoped != nil && !scoped[f.Fingerprint()] {
			fmt.Fprintf(b, "  outside this change\n")
		}
	}
	flushElided()
}

// Findings in source the repository did not hand-write remain facts, but putting them in
// the application section gives them the same visual rank even when SARIF correctly says
// note. uptime-kuma measured the cost: protocol-compatibility DES in a checked-in package
// sat beside findings its maintainers could actually fix.
func writeNonApplicationFindings(b *strings.Builder, findings []taint.Finding, newness, scoped map[string]bool) {
	if len(findings) == 0 {
		return
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Provenance != findings[j].Provenance {
			return findings[i].Provenance < findings[j].Provenance
		}
		if findings[i].Analysis != findings[j].Analysis {
			return findings[i].Analysis < findings[j].Analysis
		}
		return findings[i].SinkLoc.String() < findings[j].SinkLoc.String()
	})

	fmt.Fprintf(b, "\nnon-application findings: %d, all reported and never gating\n", len(findings))
	var provenance ir.Provenance
	analysis := ""
	shown := 0
	elided := map[string]int{}
	flushElided := func() {
		if len(elided) == 0 {
			return
		}
		files := make([]string, 0, len(elided))
		for file := range elided {
			files = append(files, file)
		}
		sort.Strings(files)
		fmt.Fprintf(b, "\n  additional %s finding(s):\n", analysis)
		for _, file := range files {
			fmt.Fprintf(b, "    %-64s %d\n", file, elided[file])
		}
		elided = map[string]int{}
	}

	for _, f := range findings {
		if f.Provenance != provenance {
			flushElided()
			provenance = f.Provenance
			analysis = ""
			fmt.Fprintf(b, "\n  -- %s code --\n", provenance)
		}
		if f.Analysis != analysis {
			flushElided()
			analysis = f.Analysis
			shown = 0
			fmt.Fprintf(b, "\n  %s\n", analysis)
		}
		if shown >= sameRuleDetailLimit {
			elided[f.SinkLoc.File]++
			continue
		}
		shown++
		writeTaintFinding(b, f)
		if newness != nil && !newness[f.Fingerprint()] {
			fmt.Fprintf(b, "  in baseline: %s\n", f.Fingerprint())
		}
		if scoped != nil && !scoped[f.Fingerprint()] {
			fmt.Fprintf(b, "  outside this change\n")
		}
	}
	flushElided()
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
	// Who reads this is the whole weakness for a disclosure, so it is said on the
	// finding rather than left to be inferred from a level in another output format. The
	// negative is worth as much as the positive here: "answers an unauthenticated
	// caller" is the sentence that separates the two findings worth acting on from the
	// eight that are not.
	if f.AudienceDecides {
		if f.EntryAuthenticates {
			fmt.Fprintf(b, "  audience: a caller the entry point authenticated\n")
		} else {
			fmt.Fprintf(b, "  audience: no authentication control runs on this entry point\n")
		}
	}
	// A negative index is not a position: -1 is "the value this was called ON", and a
	// comparison has no arguments at all. Printing "argument -1" was reporting an index
	// that does not exist.
	if f.SinkArgIndex < 0 || strings.HasPrefix(f.SinkSymbol, "comparison ") {
		fmt.Fprintf(b, "  sink:  %s at %s\n", f.SinkSymbol, f.SinkLoc)
	} else {
		fmt.Fprintf(b, "  sink:  %s argument %d at %s\n", f.SinkSymbol, f.SinkArgIndex, f.SinkLoc)
	}
	for _, site := range f.RelatedSites {
		fmt.Fprintf(b, "         same weakness at %s\n", site.Loc)
	}
	if f.SinkRational != "" {
		fmt.Fprintf(b, "         %s\n", f.SinkRational)
	}

	fmt.Fprintf(b, "  flow:\n")
	for i, h := range f.Path {
		marker := ""
		if h.Resolution != "" && h.Resolution != ir.Resolved {
			marker = fmt.Sprintf("  <%s>", h.Resolution)
		}
		if h.Assumed {
			marker += "  <assumed>"
		}
		fmt.Fprintf(b, "    %d. %-28s %s%s\n", i+1, h.Loc.String(), h.Description, marker)
	}

	// The difference between a path that was followed and a path that was presumed. The
	// flow is still reported -- an unknown callee has no known semantics, and assuming
	// the taint dies there would lose real findings -- and a reader who has to decide
	// this one now knows which line to go and read.
	if len(f.Assumptions) > 0 {
		fmt.Fprintf(b, "  assumed, not established: taint is presumed to survive %s\n",
			strings.Join(f.Assumptions, ", "))
		fmt.Fprintf(b, "    nothing in this tree implements it and nothing in this model describes it\n")
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

	// A finding count answers "what did this run find". It does not answer "would this
	// build have found it", and a category with no line above is silent for one of two
	// reasons a reader cannot tell apart. This says which: how many of the weaknesses
	// the catalog puts in each category have a rule at all.
	fmt.Fprintf(b, "\n  what this build could find, per category (from the CWE ledger):\n")
	for _, c := range ledger.CoverageByCategory() {
		fmt.Fprintf(b, "    %-46s %2d of %2d weakness(es) have a rule\n", c.Category, c.Asserted, c.Total)
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
		// Whether the VIEWS were read. A server-rendered application decides its escaping
		// in files the language's compiler has never seen, so "no findings in the view
		// layer" and "the view layer was not opened" are different results and a reader
		// has to be able to tell them apart (ADR-003).
		fmt.Sprintf("templates=%t", c.Templates),
	}
	if len(c.FrameworkModels) > 0 {
		parts = append(parts, "models="+strings.Join(c.FrameworkModels, "+"))
	}
	return strings.Join(parts, " ")
}

// wrap breaks a sentence into lines no longer than width, on word boundaries.
func wrap(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	lines := []string{words[0]}
	for _, w := range words[1:] {
		last := len(lines) - 1
		if len(lines[last])+1+len(w) <= width {
			lines[last] += " " + w
			continue
		}
		lines = append(lines, w)
	}
	return lines
}
