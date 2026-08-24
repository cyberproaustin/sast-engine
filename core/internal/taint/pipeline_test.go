package taint_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/baseline"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/scan"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

func loadIR(t *testing.T, name string) *ir.IR {
	t.Helper()
	f, err := os.Open("testdata/" + name + ".ir.json")
	if err != nil {
		t.Fatalf("open corpus IR: %v", err)
	}
	defer f.Close()
	doc, err := ir.Load(f)
	if err != nil {
		t.Fatalf("load corpus IR: %v", err)
	}
	return doc
}

// A fingerprint identifies a finding, not a position.
//
// This is the property a baseline rests on entirely. If adding an import above a defect
// changes its identity, then every commit that touches a file re-reports everything in
// it, and a team learns within a day that the "new findings" list means nothing.
func TestFingerprintSurvivesLineMovement(t *testing.T) {
	doc := loadIR(t, "express-idor")
	pol := loadPolicy(t, "express-idor")

	before := map[string]bool{}
	for _, f := range scan.Run(doc, model.Builtin(), pol).Taint.Findings {
		before[f.Fingerprint()] = true
	}
	if len(before) == 0 {
		t.Fatal("fixture produced no findings to fingerprint")
	}

	// Everything moves down forty lines, as it would after an import block or a
	// licence header lands at the top of the file.
	shift := func(l *ir.Loc) { l.Line += 40 }
	for _, fn := range doc.Functions {
		shift(&fn.Loc)
		for _, v := range fn.Values {
			shift(&v.Loc)
		}
		for i := range fn.Flows {
			shift(&fn.Flows[i].Loc)
		}
		for _, c := range fn.Calls {
			shift(&c.Loc)
		}
		for i := range fn.Comparisons {
			shift(&fn.Comparisons[i].Loc)
		}
		for i := range fn.Blocks {
			shift(&fn.Blocks[i].Loc)
		}
	}

	after := scan.Run(doc, model.Builtin(), pol).Taint.Findings
	if len(after) != len(before) {
		t.Fatalf("shifting lines changed the finding count: %d -> %d", len(before), len(after))
	}
	for _, f := range after {
		if !before[f.Fingerprint()] {
			t.Errorf("finding %s at %s changed identity when its line moved", f.CWE, f.SinkLoc)
		}
	}
}

// A baselined finding is still reported and still counted. It only stops gating.
//
// The distinction matters: a baseline records that something was already there, and
// makes no claim that it is acceptable. A tool that hid baselined findings would be a
// suppression list wearing a different name, and would let a real defect disappear the
// moment someone regenerated the file.
func TestBaselineStopsGatingWithoutHidingAnything(t *testing.T) {
	doc := loadIR(t, "express-idor")
	pol := loadPolicy(t, "express-idor")

	fresh := scan.Run(doc, model.Builtin(), pol)
	if !fresh.Gating() {
		t.Fatal("fixture no longer gates, so this test cannot show a baseline stopping it")
	}

	var entries []baseline.Entry
	for _, f := range fresh.Taint.Findings {
		entries = append(entries, baseline.Entry{Fingerprint: f.Fingerprint(), CWE: f.CWE, Policy: f.Analysis})
	}
	var buf bytes.Buffer
	if err := baseline.Write(&buf, entries); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	b, err := baseline.Read(&buf)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}

	baselined := scan.Run(doc, model.Builtin(), pol)
	baselined.Baseline = b

	if baselined.Gating() {
		t.Error("a fully baselined run still gated")
	}
	if len(baselined.Taint.Findings) != len(fresh.Taint.Findings) {
		t.Errorf("the baseline hid findings: %d -> %d",
			len(fresh.Taint.Findings), len(baselined.Taint.Findings))
	}
	for _, f := range baselined.Taint.Findings {
		if baselined.IsNew(f) {
			t.Errorf("finding %s was recorded but still reads as new", f.Fingerprint())
		}
	}
}

// A finding the baseline does not know is new, and gates, even when its neighbours are
// recorded. This is the whole point of adopting the tool on an existing codebase.
func TestUnrecordedFindingStillGates(t *testing.T) {
	doc := loadIR(t, "express-idor")
	pol := loadPolicy(t, "express-idor")

	fresh := scan.Run(doc, model.Builtin(), pol)
	var gating *taint.Finding
	for i, f := range fresh.Taint.Findings {
		if f.EntryAnchored && f.Confidence.Gating() {
			gating = &fresh.Taint.Findings[i]
			break
		}
	}
	if gating == nil {
		t.Fatal("fixture has no gating finding to leave out of the baseline")
	}

	var entries []baseline.Entry
	for _, f := range fresh.Taint.Findings {
		if f.Fingerprint() == gating.Fingerprint() {
			continue // the one the team has not seen
		}
		entries = append(entries, baseline.Entry{Fingerprint: f.Fingerprint(), CWE: f.CWE, Policy: f.Analysis})
	}
	var buf bytes.Buffer
	if err := baseline.Write(&buf, entries); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	b, err := baseline.Read(&buf)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}

	res := scan.Run(doc, model.Builtin(), pol)
	res.Baseline = b
	if !res.Gating() {
		t.Error("a finding absent from the baseline did not gate")
	}
}

// A baseline the engine cannot parse must fail loudly. Accepting it would match nothing
// and read exactly like a clean codebase.
func TestUnreadableBaselineIsAnError(t *testing.T) {
	for name, doc := range map[string]string{
		"wrong format":   `{"format":"something-else","entries":[]}`,
		"unknown key":    `{"format":"sast-baseline/v1","entries":[],"ignore":["CWE-78"]}`,
		"no fingerprint": `{"format":"sast-baseline/v1","entries":[{"cwe":"CWE-78"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := baseline.Read(bytes.NewBufferString(doc)); err == nil {
				t.Error("accepted a baseline it could not have matched against")
			}
		})
	}
}

// Scoping decides what GATES, never what is reported.
//
// A pipeline asking "what did this change introduce" still needs the rest of the report
// to be true. If a scoped run hid the findings it did not gate on, the output would be a
// function of the diff rather than of the code, and a reviewer reading "no findings"
// would have no way to tell which of the two they were looking at.
func TestScopeNarrowsGatingWithoutHidingFindings(t *testing.T) {
	doc := loadIR(t, "express-idor")
	pol := loadPolicy(t, "express-idor")

	full := scan.Run(doc, model.Builtin(), pol)
	if !full.Gating() {
		t.Fatal("fixture no longer gates, so scoping cannot be shown to stop it")
	}

	scoped := scan.Run(doc, model.Builtin(), pol)
	scoped.Changed = map[string]bool{"nothing-here.ts": true}

	if scoped.Gating() {
		t.Error("a finding outside the change set gated the run")
	}
	if len(scoped.Taint.Findings) != len(full.Taint.Findings) {
		t.Errorf("scoping hid findings: %d -> %d", len(full.Taint.Findings), len(scoped.Taint.Findings))
	}
	for _, f := range scoped.Taint.Findings {
		if scoped.InScope(f) {
			t.Errorf("finding at %s reads as in-scope for an unrelated change", f.SinkLoc)
		}
	}
}

// A change to any file the flow passes through brings the finding into scope, not just
// the file holding the dangerous operation.
func TestScopeFollowsTheWholeEvidencePath(t *testing.T) {
	doc := loadIR(t, "express-command-injection")

	res := scan.Run(doc, model.Builtin(), nil)
	if len(res.Taint.Findings) == 0 {
		t.Fatal("fixture produced no findings")
	}

	var crossFile taint.Finding
	for _, f := range res.Taint.Findings {
		if f.SourceLoc.File != f.SinkLoc.File {
			crossFile = f
			break
		}
	}
	if crossFile.CWE == "" {
		t.Skip("fixture has no finding that crosses a file boundary")
	}

	// Scoped to the file the SOURCE is in; the sink lives elsewhere.
	scoped := scan.Run(doc, model.Builtin(), nil)
	scoped.Changed = map[string]bool{crossFile.SourceLoc.File: true}
	if !scoped.InScope(crossFile) {
		t.Errorf("a change to %s did not bring in scope a flow that starts there and ends in %s",
			crossFile.SourceLoc.File, crossFile.SinkLoc.File)
	}
}

// An empty change set means the change touched nothing, which is a real answer and not
// the same as declining to scope. Treating it as "no scope" would silently widen a run
// back to the whole tree at exactly the moment it was asked to narrow.
func TestEmptyChangeSetGatesNothing(t *testing.T) {
	doc := loadIR(t, "express-idor")
	pol := loadPolicy(t, "express-idor")

	res := scan.Run(doc, model.Builtin(), pol)
	res.Changed = map[string]bool{}
	if res.Gating() {
		t.Error("an empty change set still gated")
	}
}

// A control on every entry point distinguishes none of them (ADR-010).
//
// On real code every control reads "unclassified": nothing separates an authentication
// guard from a rate limiter by name, and one production codebase applies a throttler to
// all 39 of its routes. What the population can answer is which controls vary. The
// nestjs-controller fixture has both shapes, an app-scoped guard on every route and a
// route-scoped one on a single route, and the engine must tell them apart without being
// told what either is for.
func TestUniversalControlsAreDistinguishedFromDiscriminatingOnes(t *testing.T) {
	doc := loadIR(t, "nestjs-controller")
	s := scan.Run(doc, model.Builtin(), nil).Surface

	if len(s.Entries) < 2 {
		t.Fatalf("fixture has %d entry points; the population cannot say anything", len(s.Entries))
	}

	seen := map[string]bool{}
	for _, e := range s.Entries {
		for _, c := range e.Controls {
			seen[c.Name] = true
			switch c.Name {
			case "AuthGuard":
				if c.Discriminates {
					t.Errorf("AuthGuard is on all %d entry points but reads as discriminating", c.Reach)
				}
				if c.Reach != len(s.Entries) {
					t.Errorf("AuthGuard reach = %d, want %d", c.Reach, len(s.Entries))
				}
			case "AdminGuard":
				if !c.Discriminates {
					t.Errorf("AdminGuard is on %d of %d entry points but reads as universal",
						c.Reach, len(s.Entries))
				}
			}
		}
	}
	for _, want := range []string{"AuthGuard", "AdminGuard"} {
		if !seen[want] {
			t.Errorf("fixture no longer carries %s, so this proves nothing", want)
		}
	}
}

// A judgement about the caller's identity, on an entry point handed none, is set aside.
//
// The policy is right every time here and useful never: it restates that it had nothing to
// compare against. 42 findings of this shape were adjudicated by hand against sixteen
// production repositories -- login flows, OAuth callbacks, invite redemptions, webhooks --
// and the precision was 0.00, twenty-four false and eighteen disputed with nothing true.
//
// Set aside, not deleted. It is still reported, still explained, and a team that declares
// establishesIdentity gets the judgement back. And a handler that WAS handed identity and
// ignored it stays a finding, which is the case the policy exists for.
func TestJudgementWithoutCallerIdentityIsSetAsideNotCounted(t *testing.T) {
	doc := loadIR(t, "nestjs-ownership")
	res := scan.Run(doc, model.Builtin(), nil)

	if len(res.Taint.NoCallerIdentity) == 0 {
		t.Fatal("the fixture's no-identity route produced no set-aside judgement")
	}
	for _, f := range res.Taint.NoCallerIdentity {
		if !f.EntryHasNoInjectedIdentity {
			t.Errorf("%s was set aside without the fact that explains why", f.SinkLoc)
		}
		for _, kept := range res.Taint.Findings {
			if kept.Fingerprint() == f.Fingerprint() {
				t.Errorf("%s was both set aside and counted", f.SinkLoc)
			}
		}
	}

	// The case the policy exists for must survive: identity handed over and ignored.
	if len(res.Taint.Findings) == 0 {
		t.Error("setting aside the unjudgeable also removed the judgements that hold")
	}
	if res.Gating() {
		t.Error("a set-aside judgement gated the run")
	}
}

// A thin surface and a clean application produce the same report, and that is the most
// dangerous output this engine has. They are distinguishable, and this is the check.
//
// Seven of twenty-three real repositories enumerated almost nothing and reported clean:
// a Flask forum with 1,012 functions yielded zero entry points, and the only way to know
// was to notice the number by eye. Code that handles caller-supplied input and sits where
// no enumerated entry point reaches it is the evidence, and the engine can count it.
func TestThinSurfaceIsReportedAsIncompleteNotClean(t *testing.T) {
	// This corpus has parameter decorators the model knows on methods whose routing
	// decorator it does not, so it reads request data and enumerates nothing.
	blind := scan.Run(loadIR(t, "unanchored-decorator"), model.Builtin(), nil).Surface
	if len(blind.Entries) != 0 {
		t.Fatalf("fixture no longer has an empty surface: %d entries", len(blind.Entries))
	}
	if blind.Completeness.InputFunctions == 0 {
		t.Fatal("fixture reads no caller-supplied input, so it cannot show the contradiction")
	}
	if !blind.Completeness.Suspect(len(blind.Entries)) {
		t.Error("an empty surface over code that reads request data must not read as clean")
	}

	// A corpus whose routes are all recognized must not be accused of hiding any.
	whole := scan.Run(loadIR(t, "clean-express"), model.Builtin(), nil).Surface
	if len(whole.Entries) == 0 {
		t.Fatal("fixture has no entry points")
	}
	if whole.Completeness.Suspect(len(whole.Entries)) {
		t.Errorf("a fully enumerated surface was reported incomplete: %+v", whole.Completeness)
	}
}
