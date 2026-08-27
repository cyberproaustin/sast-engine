// Package assertion answers "what does this tool claim about this codebase, and what
// does it decline to claim?" (ADR-007).
//
// Three taxonomies, each doing the job it is actually good at:
//
//	CWE      the identity of a finding. Precise, stable, what everything maps FROM.
//	ASVS     what the tool asserts. Discrete, verifiable requirements — a real target.
//	Top 10   a derived reporting rollup, computed from the CWE mapping on the way out.
//
// The Top 10 is never authored on a rule. It is ten deliberately coarse awareness
// categories, and stamping one on each rule is how tools imply uniform coverage across
// all of them while their real coverage sits in two.
//
// The coverage map exists to advertise gaps. A requirement nothing asserts is reported
// as unchecked, and one static analysis cannot decide is reported as undecidable —
// both are more useful than an unqualified pass.
package assertion

import (
	"fmt"
	"sort"

	"github.com/cyberproaustin/sast-engine/core/internal/ledger"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/scan"
)

// Status is what the TOOL can do about a requirement, independent of any codebase.
type Status string

const (
	// Asserted: an analysis checks this.
	Asserted Status = "asserted"
	// Partial: checked, but only under conditions (a modeled framework, a resolvable
	// call). Reported separately so it is never mistaken for full coverage.
	Partial Status = "partial"
	// Undecidable: no static analysis can decide this. Saying so is the honest
	// answer; the alternative is a heuristic that guesses about intent (ADR-011).
	Undecidable Status = "undecidable"
	// Unchecked: decidable in principle, not built yet.
	Unchecked Status = "unchecked"
)

// State is what happened on THIS run.
type State string

const (
	Violated     State = "violated"
	Satisfied    State = "satisfied"
	NotEvaluated State = "not-evaluated"
	OutOfReach   State = "out-of-reach"
	NotBuilt     State = "not-built"
)

// Requirement is one discrete thing the tool may assert about a codebase.
type Requirement struct {
	ID      string // ASVS requirement id
	Chapter string
	Title   string
	Status  Status
	CWEs    []string
	// AssertedBy names the policies (or "expectations") that check this. Used to
	// decide whether the requirement was actually evaluated on a given run.
	AssertedBy []string
	Note       string
}

// Editions this build maps against. Stated because both taxonomies renumber between
// releases: the Top 10 reshuffled its categories in 2025, and ASVS 5.0 replaced the
// 4.0 chapter structure entirely. A rollup that does not say which edition it used is
// not verifiable.
const (
	Top10Edition = "OWASP Top Ten 2025 (as published in the CWE catalog)"
	ASVSEdition  = "OWASP ASVS 5.0.0"
)

// Top10For returns the rollup category for a CWE, or "" when unmapped.
//
// Read from the catalog rather than held here. The table this replaced was written from
// memory, and although a hand-verification later corrected it, a mapping only one person
// has ever checked is one that drifts at the next edition without anyone noticing.
func Top10For(cwe string) string { return ledger.OWASPCategory(cwe) }

// CatalogScope states the catalog's relationship to the standard it cites.
//
// Every requirement in this catalog is now asserted or explicitly out of reach, and that
// is a fact about the catalog rather than about the tool: ASVS 5.0 contains far more
// requirements than the ones listed here, and a coverage map that reports 100% of a
// hand-picked subset is the exact false completeness ADR-007 was written against.
//
// Naming the subset is the honest form of the gap. Requirements are added here only with
// an identifier verified against the published standard; a previous batch was written
// from memory and every one of the eight was wrong, which is why nothing is added on
// recollection.
const CatalogScope = "this catalog represents a subset of " + ASVSEdition +
	"; requirements not listed here are not asserted by this tool"

// Catalog is the requirement set this build of the tool knows about.
//
// It deliberately contains requirements the tool CANNOT check. A coverage map listing
// only successes is marketing.
func Catalog() []Requirement {
	return []Requirement{
		{
			ID: "1.2.5", Chapter: "V1 Encoding and Sanitization",
			Title:      "The application protects against OS command injection",
			Status:     Partial,
			CWEs:       []string{"CWE-78"},
			AssertedBy: []string{"untrusted-to-interpreter"},
			Note:       "only for command APIs described as channels, and only where the call graph resolves",
		},
		{
			ID: "1.2.4", Chapter: "V1 Encoding and Sanitization",
			Title:      "Database queries use parameterized queries, ORMs, or entity frameworks",
			Status:     Partial,
			CWEs:       []string{"CWE-89"},
			AssertedBy: []string{"untrusted-to-interpreter"},
			Note:       "detects untrusted data reaching the SQL argument of a described execution API; a parameterized call is not a finding because the channel names only the argument that is interpreted",
		},
		{
			ID: "1.2.1", Chapter: "V1 Encoding and Sanitization",
			Title:      "Output encoding is relevant for the context required",
			Status:     Partial,
			CWEs:       []string{"CWE-79"},
			AssertedBy: []string{"untrusted-to-interpreter"},
			Note:       "detects untrusted data reaching a response body parsed as markup, and records an encoder that addresses the wrong context as insufficient -- including an encoder for a JavaScript string where the value landed in a <script> element, which the element's own syntax does not accept; views are lowered too, so an unescaped interpolation is reported at the template line, wherever its context was built. The render call no longer has to name the view and build the context in the same place: a mapping handed over whole supplies the view's names through its keys, and the keys are resolved program-wide. A POSITIONAL context object -- Django's third argument, an Express handler's locals built above the call -- is not lowered by either frontend and is the remaining gap",
		},
		{
			ID: "8.2.2", Chapter: "V8 Authorization",
			Title:      "Data-specific access is restricted to consumers with explicit permissions (IDOR/BOLA)",
			Status:     Partial,
			CWEs:       []string{"CWE-639"},
			AssertedBy: []string{"unowned-record-access"},
			Note:       "requires control flow; a helper receiving actor identity is presumed to enforce",
		},
		{
			ID: "8.3.1", Chapter: "V8 Authorization",
			Title:      "Authorization rules are enforced at a trusted service layer",
			Status:     Partial,
			CWEs:       []string{"CWE-284"},
			AssertedBy: []string{"expectations"},
			Note:       "declared requirements are enforced; inferred deviations only inform",
		},
		{
			ID: "16.5.1", Chapter: "V16 Security Logging and Error Handling",
			Title:      "A generic message is returned when an unexpected or security-sensitive error occurs",
			Status:     Partial,
			CWEs:       []string{"CWE-209"},
			AssertedBy: []string{"internal-detail-outward"},
			Note:       "detects error detail reaching a described channel; cannot judge whether a message is generic enough",
		},
		{
			ID: "8.1.1", Chapter: "V8 Authorization",
			Title:  "Authorization documentation defines rules for function-level and data-specific access",
			Status: Undecidable,
			CWEs:   []string{"CWE-285"},
			Note:   "the intended entitlements are not in the code; this is what a declared policy supplies (ADR-011)",
		},
		{
			ID: "15.2.5", Chapter: "V15 Secure Coding and Architecture",
			Title:  "Documented architecture isolates dangerous functionality to prevent lateral movement",
			Status: Undecidable,
			CWEs:   []string{},
			Note:   "a deployment and design property; the tool enumerates a surface but cannot know the intended isolation",
		},
	}
}

// Evaluated is one requirement's outcome on a specific run.
type Evaluated struct {
	Requirement Requirement
	State       State
	Findings    int
	Reason      string
}

// Report is the per-run coverage map plus the derived Top 10 rollup.
type Report struct {
	Requirements []Evaluated
	Rollup       []RollupEntry
	Unmapped     []string
}

// RollupEntry is a Top 10 category with the findings that rolled into it.
type RollupEntry struct {
	Category string
	Findings int
	CWEs     []string
}

// Evaluate produces the coverage map for a scan.
func Evaluate(res scan.Result) Report {
	byCWE := map[string]int{}
	for _, f := range res.Taint.Findings {
		byCWE[f.CWE]++
	}
	for _, f := range res.Expectation.Findings {
		byCWE[f.CWE]++
	}

	// The reason a policy was skipped travels with it. "not evaluated" without the
	// cause invites the reader to assume a frontend limitation when it may be that the
	// policy had no vocabulary for this application at all.
	skipped := map[string][]string{}
	for _, s := range res.Taint.Skipped {
		skipped[s.PolicyID] = s.Missing
	}

	rep := Report{}
	for _, req := range Catalog() {
		rep.Requirements = append(rep.Requirements, evaluateOne(req, res, byCWE, skipped))
	}

	rep.Rollup, rep.Unmapped = rollup(byCWE)
	return rep
}

func evaluateOne(req Requirement, res scan.Result, byCWE map[string]int, skipped map[string][]string) Evaluated {
	switch req.Status {
	case Undecidable:
		return Evaluated{Requirement: req, State: OutOfReach, Reason: req.Note}
	case Unchecked:
		return Evaluated{Requirement: req, State: NotBuilt, Reason: req.Note}
	}

	// A requirement the engine actually caught being broken is VIOLATED, and no doubt
	// about the surface changes that. Everything below casts doubt on SILENCE -- on the
	// claim that nothing was found -- and a finding is not silence. Counting first is
	// what keeps a real defect from being softened into "not evaluated" by the engine's
	// own uncertainty about what else it might have missed.
	count := 0
	for _, cwe := range req.CWEs {
		count += byCWE[cwe]
	}
	if count > 0 {
		return Evaluated{Requirement: req, State: Violated, Findings: count, Reason: req.Note}
	}

	// An assertion whose analysis did not run has not been satisfied — it has not been
	// tested (ADR-003). Reporting it as passing is the failure this whole design
	// exists to avoid.
	if reason, ok := notEvaluated(req, res, skipped); ok {
		return Evaluated{Requirement: req, State: NotEvaluated, Reason: reason}
	}
	return Evaluated{Requirement: req, State: Satisfied, Reason: req.Note}
}

func notEvaluated(req Requirement, res scan.Result, skipped map[string][]string) (string, bool) {
	// Nothing can be asserted about an application whose surface is empty. The
	// analyses did run, and they found nothing — but they had nothing to look at, so
	// "satisfied" would be a claim about the engine's blindness rather than about the
	// code. This is the same rule as ADR-003 applied one level up: the report already
	// says "none enumerated — no analysis below can mean anything", and the coverage
	// table must not then contradict it.
	if len(res.Surface.Entries) == 0 {
		return "no entry points were enumerated, so nothing was asserted over", true
	}
	// The same argument, one step weaker and far more dangerous, because this case does
	// not look like blindness. A surface the engine ITSELF calls into question is not a
	// surface anything can be asserted over, and the report already says so on the line
	// above the coverage table -- it just used to contradict itself immediately after.
	//
	// Measured across ten unmodified repositories: jupyterhub printed "0 violated, 6
	// satisfied" having enumerated nine entry points, every one of them from its
	// examples directory and none of the sixty-two real ones. searxng printed six
	// satisfied with 128 of its 130 input-reading functions unreached. A false positive
	// wastes somebody's afternoon; this tells them their application is fine.
	//
	// The two contradictions are named apart because they call for different work. The
	// share of unreachable input-reading code says the models do not recognize how this
	// application routes; a route family the framework serves and the enumeration does
	// not contain says which FILES to go and look at, and a reason that reported the
	// other number would send a reader looking for the wrong thing.
	if routes := res.Surface.Completeness.UnenumeratedRoutes; len(routes) > 0 {
		return fmt.Sprintf(
			"the enumerated surface is incomplete: %d file(s) the framework serves at an address of their own are not among the %d enumerated, starting with %s",
			len(routes), len(res.Surface.Entries), routes[0].Module), true
	}
	if res.Surface.Completeness.Suspect(res.Surface.RemoteEntries()) {
		return fmt.Sprintf(
			"the enumerated surface is incomplete: %d function(s) read caller-supplied input that no entry point reaches, against %d enumerated",
			res.Surface.Completeness.UnreachedInputFunctions, len(res.Surface.Entries)), true
	}

	for _, by := range req.AssertedBy {
		if by == "expectations" {
			if !res.Expectation.Applicable {
				return "the expectation analysis did not run", true
			}
			continue
		}
		if !res.Taint.Applicable {
			return "the dataflow analysis did not run", true
		}
		if why, ok := skipped[by]; ok {
			return "policy " + by + " was not evaluated: " + strings.Join(why, ", "), true
		}
	}
	return "", false
}

func rollup(byCWE map[string]int) ([]RollupEntry, []string) {
	entries := map[string]*RollupEntry{}
	var unmapped []string

	for cwe, n := range byCWE {
		cat := Top10For(cwe)
		if cat == "" {
			unmapped = append(unmapped, cwe)
			continue
		}
		e, ok := entries[cat]
		if !ok {
			e = &RollupEntry{Category: cat}
			entries[cat] = e
		}
		e.Findings += n
		e.CWEs = append(e.CWEs, cwe)
	}

	var out []RollupEntry
	for _, e := range entries {
		sort.Strings(e.CWEs)
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
	sort.Strings(unmapped)
	return out, unmapped
}

// Counts summarizes states for a one-line verdict.
func (r Report) Counts() map[State]int {
	out := map[State]int{}
	for _, e := range r.Requirements {
		out[e.State]++
	}
	return out
}
