package report

import (
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// The whole point of separating the two sets is that neither one disappears. A reader
// looking for the application's defects must not have to read past a fixture's key to
// find them, and a reader looking for that key must still be able to find it -- 34 of 59
// hardcoded-secret findings in one batch were test fixtures, and the value of keeping
// them is that a real credential parked in one is still in this file.
func TestTheReportSeparatesTheTwoSetsAndPrintsBoth(t *testing.T) {
	live := taint.Finding{
		Analysis: "untrusted-to-shell", CWE: "CWE-78", Class: "Command injection",
		Message: "a caller must not choose the command", Confidence: taint.High,
		EntryPoint: "POST /run", EntryAnchored: true,
		SinkLoc: ir.Loc{File: "app/routes.ts", Line: 12},
	}
	fixture := taint.Finding{
		Analysis: "hardcoded-secret", CWE: "CWE-798", Class: "Hardcoded credential",
		Message: "a credential written into the source", Confidence: taint.High,
		EntryPoint: "loadClient()", EntryAnchored: true, InTestModule: true,
		SinkLoc: ir.Loc{File: "app/client.test.ts", Line: 44},
	}
	command := taint.Finding{
		Analysis: "untrusted-to-filesystem-path", CWE: "CWE-22", Class: "Path traversal",
		Message: "a caller must not choose the file", Confidence: taint.High,
		EntryPoint: "cli-command import [django]", EntryAnchored: true, EntryTrust: ir.Operator,
		SinkLoc: ir.Loc{File: "commands/import.py", Line: 19},
	}

	b := &strings.Builder{}
	writeTaint(b, taint.Result{Applicable: true, Findings: []taint.Finding{live, fixture, command}},
		nil, nil, func(f taint.Finding) bool { return f.Actionable() })
	out := b.String()

	for _, want := range []string{
		// The application's own defect, counted on its own.
		"app/routes.ts:12",
		"1 finding(s), 1 gating",
		// Both of the others, each under the reason it is not counted there.
		"enumerated, not reported: 2 finding(s)",
		"in a test module",
		"app/client.test.ts:44",
		"reached only at operator trust",
		"commands/import.py:19",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report does not contain %q:\n%s", want, out)
		}
	}

	// The order is the claim: a maintainer reads their own code first.
	if strings.Index(out, "app/routes.ts") > strings.Index(out, "enumerated, not reported") {
		t.Error("the application's findings must come before the ones that are only enumerated")
	}
}
