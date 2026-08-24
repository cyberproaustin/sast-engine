package ledger

import "strings"

// What this engine claims, keyed by CWE id.
//
// Only deviations from the default are listed. Everything else derives its state from the
// catalog: a Pillar or Class is abstract, something MITRE says no tool can find is
// undecidable, and anything left is not-built. That default is deliberately the
// unflattering one — a weakness nobody has thought about and a weakness deliberately
// deferred should not be distinguishable by their absence from a file.
//
// A claim without a reason is not accepted. See TestEveryClaimStatesItsReason.
var claims = map[string]Claim{
	"CWE-78": {Asserted, "untrusted data reaching a described command API, across functions and modules",
		[]string{"untrusted-to-interpreter"}},
	"CWE-73": {Asserted, "untrusted data choosing the executable a process launches",
		[]string{"untrusted-to-interpreter"}},
	"CWE-95": {Asserted, "untrusted data reaching a language evaluator: eval, Function, Python exec",
		[]string{"untrusted-to-interpreter"}},
	"CWE-89": {Partial, "untrusted data COMPOSED into the statement argument of a described SQL API; a parameterized call cannot match because the channel names only the interpreted argument",
		[]string{"untrusted-to-interpreter"}},
	"CWE-79": {Partial, "untrusted data reaching a response body parsed as markup, with context-wrong encoders recorded as insufficient; escaping decided inside a template file is out of reach because templates are not lowered",
		[]string{"untrusted-to-interpreter"}},
	"CWE-209": {Partial, "caught error detail reaching a channel visible outside the system; cannot judge whether a message is generic enough",
		[]string{"internal-detail-outward"}},
	"CWE-639": {Partial, "a record selector chosen by the caller with no relation to the caller's identity; requires control flow. Judgements on entry points the framework handed no identity are set aside rather than reported: 42 of those were adjudicated by hand against sixteen production repositories at 0.00 precision, and setting them aside cost nothing on the vulnerable corpus",
		[]string{"unowned-record-access"}},
	"CWE-284": {Partial, "an entry point missing a control most of its comparable peers apply; inferred expectations inform and never gate",
		[]string{"expectations"}},

	// Decidable in principle, and honestly not built. Listed because naming the next ones
	// is more useful than an empty space.
	"CWE-22":  {NotBuilt, "no filesystem channels are described yet", nil},
	"CWE-918": {NotBuilt, "needs outbound-request channels and a notion of caller-chosen destination", nil},
	"CWE-502": {NotBuilt, "needs deserialization channels", nil},
	"CWE-327": {NotBuilt, "a call-shape assertion rather than a flow; the analysis kind is not built", nil},
	"CWE-328": {NotBuilt, "a call-shape assertion rather than a flow; the analysis kind is not built", nil},
	"CWE-330": {NotBuilt, "a call-shape assertion rather than a flow; the analysis kind is not built", nil},
	"CWE-798": {NotBuilt, "needs literal-value classification rather than taint", nil},
	"CWE-614": {NotBuilt, "a call-shape assertion over cookie options; the analysis kind is not built", nil},

	// Real, and about something no analysis of source can see.
	"CWE-285": {Undecidable, "the intended entitlements are not in the code; a declared policy is what supplies them (ADR-011)",
		nil},
	"CWE-1104": {Undecidable, "whether a dependency is maintained is a fact about the world, not about this source", nil},
}

// claimFor returns what the engine says about a weakness, defaulting from the catalog.
func claimFor(w Weakness) Claim {
	if c, ok := claims[w.ID]; ok {
		return c
	}
	switch {
	case w.Status == "Deprecated":
		return Claim{OutOfScope, "withdrawn from the catalog", nil}
	case !w.HasCodeShape():
		return Claim{Abstract, "a " + strings.ToLower(w.Abstraction) +
			", covered by covering the weaknesses beneath it rather than directly", nil}
	case !w.StaticDetectable:
		return Claim{Undecidable, "the catalog records no static-analysis detection method for it", nil}
	case !w.LanguageAgnostic && !ours(w.Languages):
		return Claim{OutOfScope, "specific to a language this engine has no frontend for", nil}
	}
	return Claim{NotBuilt, "no rule has been written for it", nil}
}

func ours(langs []string) bool {
	for _, l := range langs {
		switch l {
		case "JavaScript", "TypeScript", "Python", "PHP", "Java", "Ruby", "Go":
			return true
		}
	}
	return false
}
