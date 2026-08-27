package taint_test

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// The corpus asserts that both flows are FOUND, which is the policy decision: taint keeps
// crossing a call into code that is not in the tree. What a corpus cannot assert is the
// difference between them, because a corpus scores a CWE at a line and both of these have
// one. This is that difference.
//
// It matters because the two doubts are separate and were being reported as one. A finding
// whose call graph resolved badly is uncertain about WHERE the value went; a finding that
// crossed an unread dependency is certain about where it went and uncertain about whether
// it survived. Seven uptime-kuma findings were adjudicated disputed for the second reason
// while the report only ever expressed the first.
func TestAnUnreadDependencyIsNamedAndAModelledCallIsNot(t *testing.T) {
	res := taint.Analyze(loadIR(t, "absent-dependency"), model.Builtin())
	if !res.Applicable {
		t.Fatal("analysis did not run")
	}

	byLine := map[int]taint.Finding{}
	for _, f := range res.Findings {
		byLine[f.SinkLoc.Line] = f
	}

	badge, ok := byLine[15]
	if !ok {
		t.Fatal("no finding at the badge sink; the decision is that taint SURVIVES an unread callee")
	}
	if len(badge.Assumptions) != 1 || badge.Assumptions[0] != "badge-maker.makeBadge" {
		t.Errorf("want the unread dependency named exactly once, got %v", badge.Assumptions)
	}

	shell, ok := byLine[24]
	if !ok {
		t.Fatal("no finding at the shell sink")
	}
	if len(shell.Assumptions) != 0 {
		t.Errorf("encodeURIComponent is described by this model, so nothing here was assumed; got %v",
			shell.Assumptions)
	}
	// And the model's statement about it is still made, in the place it belongs.
	if len(shell.Sanitizers) == 0 {
		t.Error("want the traversed transform reported as insufficient for a shell")
	}
}

// A hop the model describes must not be marked assumed, whichever kind of statement the
// model makes about it. Asked directly, because the finding-level test above can only see
// the two calls one fixture happens to contain.
func TestAttestsCoversEveryKindOfStatementTheModelMakes(t *testing.T) {
	m := model.Builtin()

	described := []struct{ symbol, method string }{
		{"child_process.exec", "exec"},      // a channel
		{"encodeURIComponent", ""},          // a transform
		{"crypto.createHash", "createHash"}, // a classification source
		{"JSON.stringify", "stringify"},     // a carrier
		{"", "then"},                        // a callback
		{"Promise", ""},                     // a continuation
	}
	for _, d := range described {
		if !m.Attests(d.symbol, d.method) {
			t.Errorf("model describes %q/%q and Attests says it does not", d.symbol, d.method)
		}
	}

	for _, unknown := range []string{"badge-maker.makeBadge", "feed.Feed", "some-package.doThing"} {
		if m.Attests(unknown, "") {
			t.Errorf("model says nothing about %q and Attests claims it does", unknown)
		}
	}
}
