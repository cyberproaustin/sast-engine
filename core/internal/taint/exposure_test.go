package taint_test

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// Filtering by data class rather than by a flow name: the class is the property the
// analysis actually reasons about (ADR-012).
func findingsFor(res []taint.Finding, dataClass string) []taint.Finding {
	var out []taint.Finding
	for _, f := range res {
		if f.DataClass == dataClass {
			out = append(out, f)
		}
	}
	return out
}

// The exposure flow runs the same engine in the opposite direction: the source is
// sensitive rather than untrusted, and the sink is externally visible rather than
// dangerous.
func TestExposureFlowFindsErrorDetailReachingResponse(t *testing.T) {
	res := runScan(t, "express-error-leak")

	found := findingsFor(res.Taint.Findings, "internal-error")
	if len(found) != 1 {
		t.Fatalf("want 1 exposure finding, got %d: %+v", len(found), found)
	}

	f := found[0]
	if f.CWE != "CWE-209" {
		t.Errorf("want CWE-209, got %s", f.CWE)
	}
	// The finding must state the judgement, not just the location.
	if f.Analysis != "internal-detail-outward" {
		t.Errorf("finding should name the policy violated, got %q", f.Analysis)
	}
	if f.Visibility != "public" {
		t.Errorf("finding should state the channel visibility, got %q", f.Visibility)
	}
	if f.ChannelID != "http-response-body" {
		t.Errorf("finding should name the channel, got %q", f.ChannelID)
	}
	if f.SourceLabel != "err" {
		t.Errorf("want the caught error as the source, got %q", f.SourceLabel)
	}
	if f.EntryPoint != "GET /api/orders/:id [express]" {
		t.Errorf("wrong entry point: %s", f.EntryPoint)
	}
	if len(f.Path) < 3 {
		t.Errorf("exposure findings carry evidence too; got %d hops", len(f.Path))
	}
}

// Keeping an error server-side is the correct handling. Logging it is not exposing
// it, and a tool that cannot tell the difference makes correct code look wrong.
func TestLoggedErrorIsNotAnExposure(t *testing.T) {
	res := runScan(t, "express-error-leak")
	for _, f := range findingsFor(res.Taint.Findings, "internal-error") {
		if f.EntryPoint == "GET /api/health [express]" {
			t.Errorf("console.error is not an exposure sink: %+v", f)
		}
	}
}

// A sink matched by method name means nothing without knowing what it was called on.
// `auditSink.json(...)` carries the same error detail and is not a response.
func TestResponseSinkRequiresAResponseReceiver(t *testing.T) {
	res := runScan(t, "express-error-leak")
	for _, f := range findingsFor(res.Taint.Findings, "internal-error") {
		if f.EntryPoint == "GET /api/audit [express]" {
			t.Errorf("`.json()` on a non-response object must not match: %+v", f)
		}
	}
}

// Each flow propagates independently. If they shared taint state, request data could
// satisfy an exposure sink and error detail could satisfy a shell sink.
func TestFlowsDoNotCrossContaminate(t *testing.T) {
	leak := runScan(t, "express-error-leak")
	if got := findingsFor(leak.Taint.Findings, "untrusted-input"); len(got) != 0 {
		t.Errorf("no dangerous sinks exist in this corpus, got %d: %+v", len(got), got)
	}

	inject := runScan(t, "express-command-injection")
	if got := findingsFor(inject.Taint.Findings, "internal-error"); len(got) != 0 {
		t.Errorf("no sensitive sources exist in this corpus, got %d: %+v", len(got), got)
	}
	// Counted by channel rather than in total. The corpus legitimately reflects the same
	// values into an HTML response as well as running them through a shell, and a bare
	// total would have to be re-tuned every time the model learns a destination -- which
	// is not the property under test. The property is that adding a second CLASS of flow
	// leaves this one exactly as it was.
	shell := 0
	for _, f := range findingsFor(inject.Taint.Findings, "untrusted-input") {
		if f.SinkContext == "shell" {
			shell++
		}
	}
	if shell != 2 {
		t.Errorf("adding a second flow changed the first: want 2 shell findings, got %d", shell)
	}
}

// Every finding carries the full judgement: what the data was, where it went, who can
// see that, and which policy forbids the pairing.
func TestEveryFindingStatesItsJudgement(t *testing.T) {
	for _, name := range []string{"express-error-leak", "express-command-injection", "express-async"} {
		res := runScan(t, name)
		for _, f := range res.Taint.Findings {
			if f.DataClass == "" || f.ChannelID == "" || f.Visibility == "" || f.Analysis == "" {
				t.Errorf("%s: finding is missing part of its judgement: %+v", name, f)
			}
		}
	}
}

// The ADR-012 test, made executable.
//
// Internal detail forwarded to a third-party webhook is a defect class nobody wrote a
// rule for. It is caught because the model describes what an outbound HTTP call IS —
// a channel visible outside this trust boundary — and an existing policy already says
// internal failure detail must not reach one. The SAME policy covers the HTTP response
// body. One judgement, two channels, and it would cover the next channel too.
func TestOnePolicyCoversChannelsItNeverEnumerated(t *testing.T) {
	response := findingsFor(runScan(t, "express-error-leak").Taint.Findings, "internal-error")
	webhook := findingsFor(runScan(t, "express-webhook-leak").Taint.Findings, "internal-error")

	if len(response) != 1 || len(webhook) != 1 {
		t.Fatalf("want one finding in each corpus, got %d and %d", len(response), len(webhook))
	}
	if response[0].Analysis != webhook[0].Analysis {
		t.Fatalf("two channels should violate the SAME judgement; got %q and %q",
			response[0].Analysis, webhook[0].Analysis)
	}
	if response[0].ChannelID == webhook[0].ChannelID {
		t.Errorf("the point is that the channels differ; both were %q", response[0].ChannelID)
	}
	if response[0].Visibility != "public" || webhook[0].Visibility != "thirdparty" {
		t.Errorf("visibility should distinguish them: got %q and %q",
			response[0].Visibility, webhook[0].Visibility)
	}
}

// Policy does real work in both directions. Forwarding a caller's own input to a third
// party is not a boundary violation, and no rule should invent one — that would flag
// every integration in the codebase.
func TestNoPolicyMeansNoFinding(t *testing.T) {
	res := runScan(t, "express-webhook-leak")
	for _, f := range res.Taint.Findings {
		if f.DataClass == "untrusted-input" && f.ChannelID == "outbound-http" {
			t.Errorf("untrusted input reaching a third party is not forbidden by any policy: %+v", f)
		}
	}
}
