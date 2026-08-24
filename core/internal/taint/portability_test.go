package taint_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/assertion"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/scan"
)

// A path that leaves a frontend must be relative to the scanned root.
//
// This is not cosmetic. An absolute path carries the checkout directory into group
// names and finding evidence, so the same commit scanned on a developer machine and
// on a build agent produces two different reports and no finding can be matched to
// its previous self. It regressed silently once: relativization was written when the
// IR had four kinds of location, and the four added later (blocks, comparisons, entry
// registration sites, middleware) were never added to it. Nothing failed, because
// nothing asserted the invariant — only the fields, not the rule, were covered.
func TestIRPathsAreRootRelative(t *testing.T) {
	for _, name := range corpora {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open("testdata/" + name + ".ir.json")
			if err != nil {
				t.Fatalf("open corpus IR: %v", err)
			}
			defer f.Close()

			doc, err := ir.Load(f)
			if err != nil {
				t.Fatalf("load corpus IR: %v", err)
			}

			check := func(where, path string) {
				t.Helper()
				if path == "" {
					return
				}
				if filepath.IsAbs(path) || strings.HasPrefix(path, "..") {
					t.Errorf("%s: path %q is not relative to the scanned root", where, path)
				}
			}

			for _, m := range doc.Modules {
				check("modules[].path", m.Path)
			}
			for _, fn := range doc.Functions {
				check("function "+fn.ID, fn.Loc.File)
				for _, v := range fn.Values {
					check("value "+v.ID, v.Loc.File)
				}
				for _, fl := range fn.Flows {
					check("flow in "+fn.ID, fl.Loc.File)
				}
				for _, c := range fn.Calls {
					check("call "+c.ID, c.Loc.File)
				}
				for _, c := range fn.Comparisons {
					check("comparison in "+fn.ID, c.Loc.File)
				}
				for _, b := range fn.Blocks {
					check("block "+b.ID, b.Loc.File)
				}
			}
			for _, ep := range doc.EntryPoints {
				check("entryPoint "+ep.FunctionID, ep.Loc.File)
				check("entryPoint detail.module", ep.Detail["module"])
				for _, mw := range ep.Middleware {
					check("middleware "+mw.Ref(), mw.Loc.File)
				}
			}
		})
	}
}

// A flow the engine cannot connect to an enumerated entry point is reported, but it is
// not an assertion over the surface and must never stop a build (ADR-009).
//
// The shape is real: frameworks share a parameter-decorator vocabulary, so a model that
// recognizes `@Body()` will seed sources inside methods whose routing decorator belongs
// to a framework this engine has never heard of. One repository in the validation set
// produced 81 findings this way against 6 enumerated entry points — a finding list
// eighty percent composed of claims about an attack surface that was never mapped.
func TestUnanchoredFlowIsReportedButNeverGates(t *testing.T) {
	f, err := os.Open("testdata/unanchored-decorator.ir.json")
	if err != nil {
		t.Fatalf("open corpus IR: %v", err)
	}
	defer f.Close()

	doc, err := ir.Load(f)
	if err != nil {
		t.Fatalf("load corpus IR: %v", err)
	}

	res := scan.Run(doc, model.Builtin(), nil)

	if len(res.Surface.Entries) != 0 {
		t.Fatalf("fixture no longer has an empty surface: %d entries", len(res.Surface.Entries))
	}
	if len(res.Taint.Findings) != 1 {
		t.Fatalf("want the flow to still be found, got %d findings", len(res.Taint.Findings))
	}

	got := res.Taint.Findings[0]
	if got.EntryAnchored {
		t.Errorf("finding claims an entry point, but none was enumerated")
	}
	if !got.Confidence.Gating() {
		t.Fatalf("fixture no longer exercises the case: confidence %q would not gate anyway", got.Confidence)
	}
	if res.Gating() {
		t.Errorf("an unanchored finding gated the run")
	}

	// Nothing may be reported as satisfied when nothing was enumerated.
	for _, req := range assertion.Evaluate(res).Requirements {
		if req.State == assertion.Satisfied {
			t.Errorf("requirement %s reported satisfied over an empty surface", req.Requirement.ID)
		}
	}
}

// An input the frontend could not read cannot support a conclusion about what the
// handler did with its inputs (ADR-003).
//
// This is the monorepo shape: the scan is rooted at one service, the decorator that
// injects the caller's identity is defined in a sibling package, and the engine sees a
// parameter decorator it has never met. Concluding "identity was never consulted" there
// is a statement about the scan. On one production repository it produced 66 findings,
// every one of which disappeared when the sibling package was added to the root — same
// code, same engine, a different directory.
func TestUnresolvedInputBlocksTheOwnershipJudgement(t *testing.T) {
	f, err := os.Open("testdata/nestjs-unresolved-input.ir.json")
	if err != nil {
		t.Fatalf("open corpus IR: %v", err)
	}
	defer f.Close()

	doc, err := ir.Load(f)
	if err != nil {
		t.Fatalf("load corpus IR: %v", err)
	}
	res := scan.Run(doc, model.Builtin(), nil)

	// The fixture must keep exercising the case: an unscoped selector reached by
	// caller-supplied data, which without the unresolved input would be a finding.
	if len(res.Surface.Entries) != 1 || len(res.Surface.Entries[0].EntryPoint.UnresolvedParams) == 0 {
		t.Fatalf("fixture no longer has an entry point with an unresolved input")
	}
	if len(res.Taint.Findings) != 0 {
		t.Errorf("claimed %d finding(s) over an input it could not read", len(res.Taint.Findings))
	}

	var said bool
	for _, u := range res.Taint.Unjudged {
		if u.PolicyID == "unowned-record-access" && strings.Contains(u.Reason, "UserSession") {
			said = true
		}
	}
	if !said {
		t.Errorf("the judgement was skipped without saying which input could not be resolved")
	}
}
