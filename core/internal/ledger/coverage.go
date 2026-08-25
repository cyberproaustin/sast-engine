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
	"CWE-284": {Partial, "an entry point missing a control the engine could not classify, which most of its comparable peers apply. Reported at this level deliberately: naming it authentication or authorization would be claiming to know which, and the honest identity is the class above both",
		[]string{"expectations"}},

	// Decidable in principle, and honestly not built. Listed because naming the next ones
	// is more useful than an empty space.
	"CWE-22": {Partial, "untrusted data choosing the path argument of a described filesystem API; path.basename and Flask's send_from_directory are recognized as confining it",
		[]string{"untrusted-to-filesystem-path"}},
	"CWE-918": {Partial, "untrusted data forming the WHOLE destination of a described outbound request; a URL whose host is fixed by a literal leaves the caller only a path and is not reported, at the cost of missing a host composed onto a bare scheme",
		[]string{"untrusted-to-outbound-destination"}},
	"CWE-502": {Partial, "untrusted data reaching a deserializer that reconstructs objects rather than parsing data; yaml.safe_load and JSON.parse are deliberately not described because they build data and never behaviour",
		[]string{"untrusted-to-deserializer"}},
	"CWE-601": {Partial, "untrusted data forming the WHOLE destination of a redirect; a path within the application cannot leave it and is not reported",
		[]string{"untrusted-to-redirect"}},
	"CWE-328": {Partial, "a broken hash algorithm named as a literal in the call; an algorithm chosen at runtime is not matched and not guessed at",
		[]string{"weak-hash"}},
	"CWE-295": {Partial, "certificate verification disabled by a literal argument",
		[]string{"disabled-certificate-check"}},
	"CWE-327": {Partial, "a broken cipher or a mode that leaks plaintext structure, named as a literal in the call; unlike a weak hash this gates, because nothing needs encryption for a purpose that does not need encryption",
		[]string{"weak-cipher"}},
	"CWE-1333": {Partial, "untrusted data compiled as a regular expression, where a backtracking engine can be made to take exponential time on a short input",
		[]string{"untrusted-to-regex"}},
	"CWE-330": {NotBuilt, "needs a notion of which randomness is used for a security decision, which a call shape alone does not carry", nil},
	"CWE-798": {Partial, "a key argument written as a literal, matched on having been written down rather than on what it says; a key read from the environment or a vault is not a literal and never matches",
		[]string{"hardcoded-secret"}},
	// Members of the catalog's own Top 25 that apply to these languages. Named rather than
	// left blank, because this list is the closest thing the project has to a prioritised
	// backlog that nobody wrote by hand.
	"CWE-306": {Partial, "an entry point missing an authentication control most of its comparable peers apply. Inferred from the population and therefore informing rather than gating (ADR-010); it cannot distinguish an endpoint unauthenticated by design from one that forgot, which is what a declaration supplies",
		[]string{"expectations"}},
	"CWE-862": {Partial, "an entry point missing an authorization control most of its comparable peers apply; same origin and same limits as CWE-306",
		[]string{"expectations"}},
	"CWE-434": {Partial, "an uploaded file stored at a destination the caller named, which is how the caller ends up choosing the stored type. Matched on the receiver rather than the method name -- `save` and `mv` belong to every ORM record in a program, and only an upload's is called on data that arrived in the request. Partial for two reasons: the confining validation is an extension allowlist, and no shape of one is modelled yet, so a handler that checks properly still reports; and the multer-plus-fs.writeFile shape reports as CWE-22 instead, because there the untrusted value is a filename and the sink is an ordinary file write",
		[]string{"untrusted-to-stored-file-type"}},
	"CWE-476": {Undecidable, "in these languages this is a TypeError on undefined at runtime rather than a memory fault, and deciding it statically means proving nullability across a dynamic language; the value even when solved is reliability rather than security", nil},
	"CWE-770": {Partial, "an entry point missing a throttle most of its comparable peers apply, which is the observable half of this weakness. Unbounded reads and allocations are not observable at all yet, so the claim is narrow on purpose",
		[]string{"expectations"}},

	// Cookie attributes. Two of the three are claimed for an explicit downgrade AND for
	// an omission; Secure is claimed only for the downgrade, because the correct idiom
	// makes it conditional on the environment and a rule demanding a literal would report
	// every application that does the right thing.
	"CWE-1004": {Partial, "a credential-carrying cookie set with no httpOnly attribute, or with one written as false. Claimed only where the option keys were actually enumerated: options built in another function are unknowable and are passed over in silence, which is four sites in one production file. Which cookies carry credentials is decided by name, used to narrow an existing match rather than to make one, so the failure mode is a stated miss rather than a false alarm",
		[]string{"cookie-not-http-only", "cookie-http-only-disabled"}},
	"CWE-614": {Partial, "a credential cookie with Secure explicitly disabled. Absence is deliberately not claimed: `secure: process.env.NODE_ENV === \"production\"` is correct and is not a literal",
		[]string{"cookie-not-secure"}},
	"CWE-1275": {Partial, "a credential cookie with SameSite=None. Reported and never gating, because an embedded widget and an OAuth flow both legitimately need it and the call does not carry which case this is",
		[]string{"cookie-same-site-none"}},

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
