package taint

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

// Siblings of one rule at one sink are one weakness each, and a fingerprint has to say so.
//
// juice-shop serves directory listings of `/ftp`, `/encryptionkeys` and `/support/logs`
// from three `serveIndex(...)` calls in one function. All three are separately real, all
// three were separately adjudicated by hand, and all three came out as `ef8b2b65e604649e`
// -- so a baseline entry recording ONE of them suppressed all three, and a verdict about
// one answered for all three. A real finding could be lost by having judged its
// neighbour.
func TestSiblingsOfOneRuleAtOneSinkAreNotOneFinding(t *testing.T) {
	listing := Finding{
		Analysis:     "directory-listing",
		CWE:          "CWE-548",
		EntryPoint:   "start()",
		SinkLoc:      ir.Loc{File: "server.ts", Line: 288},
		SinkFunction: "start",
		SinkSymbol:   "serve-index.default",
		SourceLabel:  `"serve-index.default()"`,
	}
	ftp, keys := listing, listing
	ftp.Discriminator = `0="ftp"`
	// The other listing, further down the same function. Only the argument differs, and
	// the line number is deliberately absent from both (ADR-014) -- so the argument is
	// the only thing that can tell them apart.
	keys.SinkLoc.Line = 296
	keys.Discriminator = `0="encryptionkeys"`

	if ftp.Fingerprint() == keys.Fingerprint() {
		t.Fatalf("two directories published by two calls share one fingerprint %s", ftp.Fingerprint())
	}

	// Position independence is the whole reason a fingerprint exists, and it survives.
	moved := ftp
	moved.SinkLoc.Line = 999
	if moved.Fingerprint() != ftp.Fingerprint() {
		t.Error("adding lines above a finding turned it into a different finding")
	}

	// Two calls written identically in one function still share a fingerprint. That is
	// correct and it is what the doc comment promises: nothing about them differs except
	// where they sit, and where they sit is not part of the identity.
	twin := ftp
	twin.SinkLoc.Line = 400
	if twin.Fingerprint() != ftp.Fingerprint() {
		t.Error("two indistinguishable findings stopped being the same finding")
	}
}

// The ledger holds 131 hand adjudications keyed by this value, and a rule that does not
// distinguish its siblings must keep hashing exactly as it did the day they were written.
//
// A constant rather than a comparison, because the thing being protected is the value
// itself: any change to the fields, their order, the separator or the digest length
// orphans every verdict at once, and a test that computed the expectation the same way
// the code does would agree with the mistake.
func TestAFindingWithNothingToDiscriminateKeepsItsRecordedFingerprint(t *testing.T) {
	f := Finding{
		Analysis:     "untrusted-to-interpreter",
		CWE:          "CWE-79",
		EntryPoint:   "GET /links [express]",
		SinkLoc:      ir.Loc{File: "app.js", Line: 42},
		SinkFunction: "render",
		SinkSymbol:   "res.send",
		SourceLabel:  "req.query.q",
	}
	const recorded = "1666baec2c05f75c"
	if got := f.Fingerprint(); got != recorded {
		t.Fatalf("fingerprint is %s, was %s -- every verdict keyed by the old value is now orphaned", got, recorded)
	}
	// And the discriminator is genuinely absent from the hash rather than being hashed as
	// an empty string, which is what makes the value above survivable at all.
	blank := f
	blank.Discriminator = ""
	if blank.Fingerprint() != recorded {
		t.Error("an empty discriminator changed the fingerprint")
	}
}
