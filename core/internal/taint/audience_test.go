package taint_test

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// An error-detail finding is worth acting on in proportion to who reads it, and until now
// the engine published every one of them at one rank.
//
// Nine of linkwarden's twenty-one findings were this rule. Eight were adjudicated true
// and not one was worth reporting: every one hands a library error string to a caller who
// already holds the account. The same rule produced two of the batch's four
// worth-reporting findings in uptime-kuma, where the endpoints answer anybody at all.
// Same rule, same weakness, and a reader with no way to tell the two apart stops reading
// the rule -- which is how the two that mattered would have been lost among the eight.
//
// All three are still findings. The audience lowers a rank; it never suppresses.
func TestErrorDetailRecordsWhoCanReadIt(t *testing.T) {
	res := runScan(t, "error-detail-audience")

	byEntry := map[string]taint.Finding{}
	for _, f := range findingsFor(res.Taint.Findings, "internal-error") {
		byEntry[f.EntryPoint] = f
	}
	if len(byEntry) != 3 {
		t.Fatalf("want three disclosures, got %d: %v", len(byEntry), byEntry)
	}

	for _, c := range []struct {
		entry         string
		authenticates bool
		why           string
	}{
		{"GET /api/status/:id [express]", false,
			"nothing on this route asks who the caller is, so the driver message goes to whoever asked"},
		{"GET /api/reports/:id [express]", true,
			"verifyUser is called in the handler itself"},
		{"POST /api/reports [express]", true,
			"a route that dispatches before it acts puts its control one hop below the handler, which is the shape linkwarden's eight sit in"},
	} {
		f, ok := byEntry[c.entry]
		if !ok {
			t.Errorf("no disclosure reported on %s", c.entry)
			continue
		}
		if !f.AudienceDecides {
			t.Errorf("%s: the disclosure judgement must say its weight is the audience", c.entry)
		}
		if f.EntryAuthenticates != c.authenticates {
			t.Errorf("%s: EntryAuthenticates %v, want %v — %s", c.entry, f.EntryAuthenticates, c.authenticates, c.why)
		}
	}
}

// A rank that depends on the audience must not start inventing findings to rank, and the
// control it now reads must not become a reason to stop reporting one.
func TestAuthenticationDoesNotSuppressOrInventDisclosures(t *testing.T) {
	res := runScan(t, "error-detail-audience")

	found := findingsFor(res.Taint.Findings, "internal-error")
	if len(found) != 3 {
		t.Fatalf("want 3 disclosures, got %d", len(found))
	}
	for _, f := range found {
		// A logged error is not an exposure and never was. The fourth route in the
		// fixture keeps its error server-side; if it appears here, the audience work has
		// broken the rule it was meant to rank.
		if f.EntryPoint == "GET /api/health [express]" {
			t.Errorf("logging an error is not exposing it: %s at %s", f.CWE, f.SinkLoc)
		}
	}
}

// The judgements whose weight is NOT the audience must be untouched by it. An injection
// behind a login is the same injection: the attacker's power over the system does not
// change with who they are, and only a disclosure's does.
func TestOnlyDisclosuresAreRankedByAudience(t *testing.T) {
	res := runScan(t, "express-idor")
	for _, f := range res.Taint.Findings {
		if f.AudienceDecides {
			t.Errorf("%s (%s) claims its weight is who receives it; only a disclosure may", f.Analysis, f.CWE)
		}
	}
}
