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
	"CWE-78": {State: Asserted, Reason: "untrusted data reaching a described command API, across functions and modules",
		By: []string{"untrusted-to-interpreter"}},
	"CWE-73": {State: Asserted, Reason: "untrusted data choosing the executable a process launches",
		By: []string{"untrusted-to-interpreter"}},
	"CWE-95": {State: Asserted, Reason: "untrusted data reaching a language evaluator: eval, Function, Python exec",
		By: []string{"untrusted-to-interpreter"}},
	"CWE-89": {State: Partial, Reason: "untrusted data COMPOSED into the statement argument of a described SQL API, where composed means composed into the value THIS sink receives rather than anywhere in its history. A parameterized call cannot match, because the channel names only the interpreted argument. Known imprecision: `execute` is also what a CQRS bus and a SQLAlchemy Session are called on, and neither takes a statement string -- telling them apart needs the receiver's type, which one frontend supplies patchily and the other not at all, so those report at reduced confidence rather than being excluded",
		By: []string{"untrusted-to-interpreter"}},
	// Subsumes the variants that name a PAYLOAD spelling -- script tags, script in an
	// attribute, alternate identifier characters. The rule proves untrusted data reaches
	// a response body parsed as markup and never inspects what the data says, so those
	// are the same finding at the same line. CWE-81 is excluded below, because what makes
	// it different is where the data came FROM, which this engine does look at.
	"CWE-79": {
		State: Partial,
		Reason: "untrusted data reaching a response body parsed as markup, with " +
			"context-wrong encoders recorded as insufficient; escaping decided inside a " +
			"template file is out of reach because templates are not lowered",
		By:       []string{"untrusted-to-interpreter"},
		Subsumes: true,
	},
	"CWE-81": {State: NotBuilt, Reason: "script reaching a page through an ERROR message rather than through caller-supplied input. Not subsumed by CWE-79 even though it sits beneath it: what distinguishes it is the SOURCE, and this engine classifies error detail separately from caller input precisely so it can tell them apart. A rule would pair the error class with the markup channel"},
	"CWE-209": {State: Partial, Reason: "caught error detail reaching a channel visible outside the system; cannot judge whether a message is generic enough",
		By: []string{"internal-detail-outward"}},
	// Subsumes CWE-566, which is the same weakness with the record's identifier being a
	// SQL primary key. Whether the selector is a primary key, a document id or a slug is
	// a detail the ownership question never asks about.
	"CWE-639": {State: Partial, Reason: "a record selector chosen by the caller with no relation to the caller's identity; requires control flow. Judgements on entry points the framework handed no identity are set aside rather than reported: 42 of those were adjudicated by hand against sixteen production repositories at 0.00 precision, and setting them aside cost nothing on the vulnerable corpus",
		Subsumes: true,
		By:       []string{"unowned-record-access"}},
	"CWE-321": {State: Partial, Reason: "a cryptographic key written as a literal into a call that must hold one -- the same rule as CWE-798 above, asserted in its own right because the argument positions it describes ARE key arguments. Only those three APIs; a key handed to anything else is a stated miss",
		By: []string{"hardcoded-secret"}},
	"CWE-284": {State: Partial, Reason: "an entry point missing a control the engine could not classify, which most of its comparable peers apply. Reported at this level deliberately: naming it authentication or authorization would be claiming to know which, and the honest identity is the class above both",
		By: []string{"expectations"}},

	// Decidable in principle, and honestly not built. Listed because naming the next ones
	// is more useful than an empty space.
	// Subsumes its variants. The catalog gives path traversal seventeen of them, one per
	// payload spelling -- `../filedir`, `..\filedir`, `/absolute/pathname`, a Windows UNC
	// share -- and an analysis that proves the caller controls the path never inspects
	// what the path CONTAINS. Every one of those spellings is the same finding at the
	// same line, and calling them unbuilt would put seventeen items on a to-do list that
	// no amount of work could remove.
	"CWE-22": {
		State: Partial,
		Reason: "untrusted data choosing the path argument of a described filesystem API; " +
			"path.basename and Flask's send_from_directory are recognized as confining it",
		By:       []string{"untrusted-to-filesystem-path"},
		Subsumes: true,
	},
	"CWE-918": {State: Partial, Reason: "untrusted data forming the WHOLE destination of a described outbound request; a URL whose host is fixed by a literal leaves the caller only a path and is not reported, at the cost of missing a host composed onto a bare scheme",
		By: []string{"untrusted-to-outbound-destination"}},
	"CWE-502": {State: Partial, Reason: "untrusted data reaching a deserializer that reconstructs objects rather than parsing data; yaml.safe_load and JSON.parse are deliberately not described because they build data and never behaviour",
		By: []string{"untrusted-to-deserializer"}},
	"CWE-601": {State: Partial, Reason: "untrusted data forming the WHOLE destination of a redirect; a path within the application cannot leave it and is not reported. Applications very often validate a redirect target with a helper of their own or behind an `is_safe_url` check, and whether such a check is CORRECT is not something this engine can decide -- it does not model guards at all, so those report rather than being cleared, and in a frontend without types they land below the gating tier rather than above it",
		By: []string{"untrusted-to-redirect"}},
	"CWE-328": {State: Partial, Reason: "a broken hash algorithm named as a literal in the call; an algorithm chosen at runtime is not matched and not guessed at",
		By: []string{"weak-hash"}},
	"CWE-295": {State: Partial, Reason: "certificate verification disabled by a literal argument or option: `verify=False` on a Python request, and `rejectUnauthorized: false` anywhere at all, because that option name means one thing in Node and a list of the clients it can be handed to would be wrong the moment somebody used a different one",
		By: []string{"disabled-certificate-check"}},
	"CWE-489": {State: Partial, Reason: "a debug server started with debug enabled by a literal keyword. Narrow on purpose: this is the one shape where the decision is written at the call, and debug flags read from configuration or the environment are not literals and are not matched",
		By: []string{"debug-mode-enabled"}},
	"CWE-942": {State: Partial, Reason: "credentials allowed on cross-origin requests while the origin is wildcarded or reflected. A conjunction rather than a single bad value, because either half alone is ordinary: a public API wildcards its origin, and a first-party front end sends credentials to a named one",
		By: []string{"permissive-cors"}},
	"CWE-327": {State: Partial, Reason: "a broken cipher or a mode that leaks plaintext structure, named as a literal in the call; unlike a weak hash this gates, because nothing needs encryption for a purpose that does not need encryption",
		By: []string{"weak-cipher"}},
	"CWE-1333": {State: Partial, Reason: "untrusted data compiled as a regular expression, where a backtracking engine can be made to take exponential time on a short input",
		By: []string{"untrusted-to-regex"}},
	"CWE-330": {State: NotBuilt, Reason: "needs a notion of which randomness is used for a security decision, which a call shape alone does not carry"},
	// A key written into a call that must hold one. The CATEGORY of secret is something
	// this rule does encode -- it names key arguments -- so the crypto-key variant is
	// asserted directly rather than subsumed. The password variant has its own rule now,
	// matched by option NAME rather than by argument position, which is how a connection
	// string asks for one.
	"CWE-798": {State: Partial, Reason: "a key argument written as a literal, matched on having been written down rather than on what it says; a key read from the environment or a vault is not a literal and never matches",
		By: []string{"hardcoded-secret"}},
	// Members of the catalog's own Top 25 that apply to these languages. Named rather than
	// left blank, because this list is the closest thing the project has to a prioritised
	// backlog that nobody wrote by hand.
	"CWE-306": {State: Partial, Reason: "an entry point missing an authentication control most of its comparable peers apply. Inferred from the population and therefore informing rather than gating (ADR-010); it cannot distinguish an endpoint unauthenticated by design from one that forgot, which is what a declaration supplies",
		By: []string{"expectations"}},
	"CWE-862": {State: Partial, Reason: "an entry point missing an authorization control most of its comparable peers apply; same origin and same limits as CWE-306",
		By: []string{"expectations"}},
	"CWE-434": {State: Partial, Reason: "an uploaded file stored at a destination the caller named, which is how the caller ends up choosing the stored type. Matched on the receiver rather than the method name -- `save` and `mv` belong to every ORM record in a program, and only an upload's is called on data that arrived in the request. Partial for two reasons: the confining validation is an extension allowlist, and no shape of one is modelled yet, so a handler that checks properly still reports; and the multer-plus-fs.writeFile shape reports as CWE-22 instead, because there the untrusted value is a filename and the sink is an ordinary file write",
		By: []string{"untrusted-to-stored-file-type"}},
	"CWE-476": {State: Undecidable, Reason: "in these languages this is a TypeError on undefined at runtime rather than a memory fault, and deciding it statically means proving nullability across a dynamic language; the value even when solved is reliability rather than security"},
	"CWE-770": {State: Partial, Reason: "an entry point missing a throttle most of its comparable peers apply, which is the observable half of this weakness. Unbounded reads and allocations are not observable at all yet, so the claim is narrow on purpose",
		By: []string{"expectations"}},

	"CWE-1336": {State: Partial, Reason: "untrusted data reaching a call that COMPILES a template. Every engine described here exposes property access and method calls to the template text, which is why this ends in code execution rather than in mangled markup. A template loaded from disk and rendered WITH untrusted data is not this weakness and is not reported",
		By: []string{"untrusted-to-interpreter"}},

	"CWE-611": {State: Partial, Reason: "untrusted data reaching an XML parser that resolves external entities. The two libraries described have opposite defaults and are treated accordingly: libxmljs resolves only when the call passes `noent`, so the call is read for it, while lxml's default parser resolves and is named outright. Nothing is claimed about parsers that are safe by default and can be made unsafe by configuration this engine cannot see",
		By: []string{"untrusted-to-xml-parser"}},

	"CWE-915": {State: Partial, Reason: "the caller's object handed to a record writer WHOLE rather than field by field, which is a question about structure in the same way SQL injection is a question about text: a value that became a FIELD of something is not the caller's object. Matched only where the symbol leaves no room for doubt. `update`, `create` and `save` were tried and withdrawn -- `save` is what an uploaded file is written with, `update` is already how a record is selected by its identifier, and a dictionary has all three -- so ORM-specific spellings of this weakness are a stated miss",
		By: []string{"untrusted-to-record-fields"}},

	"CWE-916": {State: Partial, Reason: "a password-hash work factor written into the call and below the floor at which it does any work worth the name. Reported and never gating: a work factor is only too low for a LOW-ENTROPY input, and the call does not carry what it was given -- deriving a key from an already-random secret with a small count is correct and reads identically. Deciding it properly means knowing the input is a password, which is a flow question this kind cannot answer alone. The thresholds are floors and deliberately not current guidance -- bcrypt at 10 is the library default -- because a rule that fired on current guidance would fire on every codebase forever and be switched off. A work factor read from configuration is not a number in the call and is not matched",
		By: []string{"weak-password-hash"}},
	"CWE-329": {State: Partial, Reason: "an initialisation vector written into the source, matched on having been written down rather than on what it says, exactly as a hardcoded key is. An IV must be unpredictable and must never repeat, and one in the source is both predictable and reused on every message",
		By: []string{"predictable-iv"}},

	"CWE-470": {State: Partial, Reason: "untrusted data naming a module for the runtime to load, which runs it. Requires a WHOLE value, which is a trade rather than a safety argument: `require(\"./handlers/\" + name)` is what every plugin loader looks like and reporting them all would make the rule unusable, but a leaf containing `../` escapes the fixed directory and is missed",
		By: []string{"untrusted-to-interpreter"}},
	"CWE-1321": {State: Partial, Reason: "the caller's object merged into another by a function that walks NESTED keys, so a `__proto__` key in it reaches the prototype every object inherits from. The named deep-merge helpers only; a merge written by hand is a loop over keys and is not matched",
		By: []string{"untrusted-to-record-fields"}},

	"CWE-378": {State: Partial, Reason: "tempfile.mktemp(), which hands back a name without creating anything and has no safe calling convention. Only that one API; a temporary file created insecurely by hand is a stated miss",
		By: []string{"insecure-temp-file"}},
	"CWE-276": {State: Partial, Reason: "a file or directory mode written into the call with the world-writable BIT set, which is the actual rule rather than a list of bad numbers -- 0o777, 0o666 and 0o1777 are wrong for the same reason. A mode computed at runtime is not matched",
		By: []string{"world-writable"}},

	// Built, measured, and withdrawn in the same sitting. Argument injection is real --
	// `spawn("git", ["clone", url])` with a url of `--upload-pack=...` runs a command of
	// the caller's choosing with no shell anywhere -- but the shape that detects it is
	// the shape of the RECOMMENDED FIX for command injection, and this engine already
	// decided that on purpose: there is a fixture route called /ping-safe and a test
	// asserting that a tainted argument array to execFile is not injection. Both failed
	// within seconds of the rule existing. A tool that reports the remediation it would
	// otherwise advise is a tool people switch off, so the miss is deliberate and the
	// reasoning is here rather than in a commit nobody reads.
	"CWE-88": {State: NotBuilt, Reason: "untrusted data reaching the argument LIST of an exec that takes one. Detectable and not reported: the shape is indistinguishable from execFile and spawn being used correctly, which is what this engine tells people to do instead of building a shell string. Deciding it properly means knowing which options the named program accepts, which is not in the source"},
	"CWE-1236": {State: Partial, Reason: "untrusted data written into a CSV a spreadsheet will later interpret, where a cell beginning with a formula character runs on the machine of whoever opens it. The named writers only, and nothing is claimed about whether the application prefixes cells to defuse them, because no such convention is modelled",
		By: []string{"untrusted-to-spreadsheet"}},

	"CWE-497": {State: Partial, Reason: "the process environment reaching a response body or an outbound request WHOLE. One variable published on purpose is ordinary and is not reported: the classification is the environment itself, not anything read out of it, and a value that was projected on its way to the sink is excluded again there. Only the environment; a configuration object an application builds itself is not described",
		By: []string{"environment-outward"}},

	"CWE-532": {State: Partial, Reason: "a credential the CALLER sent reaching a log. The name list decides a classification over request PATHS rather than over local variable names, which is the whole reason it works: matching credential-shaped locals was measured across twenty clean repositories first and every match was a counter of language-model tokens. A one-way hash ends the classification, because a password hash is not a password anywhere. Credentials the application holds rather than receives are not covered, and the named loggers only",
		By: []string{"credential-recorded"}},

	"CWE-319": {State: Partial, Reason: "a credential the caller sent reaching the body of an outbound request whose destination is written into the call as a plaintext URL. The qualifier is the whole rule -- `https://` does not contain `http://` -- so the same channel says nothing about the overwhelming majority of outbound calls. A destination assembled at runtime is not a literal and is not matched",
		By: []string{"credential-in-cleartext"}},

	"CWE-201": {State: Partial, Reason: "a credential the CALLER SENT coming back in the response, where it reaches proxies, caches and browser history. Narrow precisely because of whose credential it is: a login endpoint returning a freshly issued token is returning something it generated, which is the point of a login endpoint and is not this",
		By: []string{"credential-echoed"}},

	// Measured three times and not built, which is worth recording so a fourth pass does
	// not spend the same effort. Math.random appears 90 times across the clean corpus and
	// random.choice and random.randint another 18, and almost every one is a jitter, a
	// sample or a placeholder. What decides the weakness is whether the value becomes
	// something that must be unguessable -- a token, a reset link, a session id -- and
	// that is a flow question with no sink described for it. A DependsOnUse rule would
	// mean a hundred permanent advisories nobody reads.
	// Declined three times and then built, once a sink existed that needs unguessability.
	// The reasoning that declined it was right and was about the SOURCE: Math.random
	// appears 90 times across the clean corpus and almost all of it is jitter, sampling
	// and placeholders, so the call alone says nothing. Cookie values gave the rule the
	// other half.
	"CWE-338": {State: Partial, Reason: "a number from a generator built for speed reaching a place that requires unguessability -- currently a cookie value, where guessing one is being that user. Classified at the source and judged at the SINK, which is the only place the question can be answered; the same call somewhere else in the same file is a retry delay and is not reported",
		By: []string{"predictable-secret"}},

	"CWE-336": {State: Partial, Reason: "a pseudo-random generator seeded with a constant written into the call, which makes every run produce the same sequence. The named seeding APIs only; a generator seeded from a value computed at runtime is not matched, and whether the sequence is used for anything that needs to be unguessable is the separate question CWE-338 is declined over",
		By: []string{"fixed-seed"}},
	"CWE-347": {State: Partial, Reason: "signature verification switched OFF by name in the call. Matching `decode()` itself was tried and withdrawn: reading a token to look at it is ordinary -- taking the issuer to choose a key, taking the expiry -- and 58 sites across the clean corpus do exactly that, so the defect is trusting the claims afterwards and the call does not carry it. A nested options dict is not flattened by either frontend, so PyJWT's `options={\"verify_signature\": False}` spelling is a stated miss while the flat keywords are matched",
		By: []string{"unverified-signature"}},
	"CWE-259": {State: Partial, Reason: "a password written into the source as the option of a call that OPENS A CONNECTION, matched by option name rather than by argument position because that is how every such library asks for one. Scoped to those calls deliberately: matching any call with a password option was tried and produced 265 findings across the clean corpus, almost all test helpers and assertions. A password read from the environment is not a literal; an option whose key is known while its value was not written down is treated as absent",
		By: []string{"hardcoded-password"}},
	"CWE-297": {State: Partial, Reason: "a TLS connection told not to check the certificate's hostname, which accepts any valid certificate rather than the one belonging to the host being talked to. The literal keyword only",
		By: []string{"no-hostname-check"}},

	"CWE-90": {State: Partial, Reason: "untrusted data COMPOSED into an LDAP filter, where a `*` in the wrong place turns a check for one user into a match for any. Composition is required to keep the rule precise on the common shape, and unlike SQL it costs a real miss: an LDAP filter ARGUMENT passed whole is the whole filter, not a parameter, so the caller writing all of it is not reported",
		By: []string{"untrusted-to-interpreter"}},
	"CWE-643": {State: Partial, Reason: "untrusted data composed into an XPath expression, which selects whichever nodes the caller names rather than the ones the application meant. The named evaluation APIs only",
		By: []string{"untrusted-to-interpreter"}},
	"CWE-757": {State: Partial, Reason: "an obsolete TLS version named in the call, either requested outright or accepted as a floor. Only versions written as literals; a version read from configuration is not matched, and nothing is claimed about what a peer actually negotiates",
		By: []string{"obsolete-tls"}},

	"CWE-315": {State: Partial, Reason: "a credential the caller sent stored as a cookie VALUE, which puts it on a machine the application does not control and sends it on every subsequent request. Whether the value is encrypted is not decidable from the call, so a signed or sealed cookie reports too -- stated rather than guessed at",
		By: []string{"credential-in-cookie"}},
	"CWE-539": {State: Partial, Reason: "the same value in a cookie carrying an EXPIRY, which is what makes it persistent: it survives the browser closing and sits on disk until the date passes. The expiry option must be written in the call",
		By: []string{"credential-in-persistent-cookie"}},
	"CWE-548": {State: Partial, Reason: "a directory listing served by the one middleware that generates them. Publishing file names publishes a map of everything in the directory, including whatever was left there. Nothing is claimed about a listing an application builds itself",
		By: []string{"directory-listing"}},

	"CWE-598": {State: Partial, Reason: "a credential the caller sent placed in a URL, which is the least private part of a request: it reaches the access log at both ends, the Referer header of whatever the page loads next, and browser history. Denied over TLS too, because none of those are on the network",
		By: []string{"credential-in-url"}},
	"CWE-426": {State: Partial, Reason: "untrusted data added to sys.path, which decides where the next import comes from. Matched by SYMBOL rather than by method name: `insert` and `append` belong to every list, ORM repository and zip archive, and matching by name produced eight findings across the clean corpus of which none was a search path. Setting PATH by assignment is not a call and is a stated miss",
		By: []string{"untrusted-search-path"}},

	// Subsumes CWE-113, which is this weakness with the line-oriented protocol named as
	// HTTP. The rule proves a caller reaches a header value and never inspects what the
	// value contains, so the two are the same finding at the same line.
	"CWE-93": {
		State: Partial,
		Reason: "untrusted data reaching a response header value, where a line break ends " +
			"the header and begins whatever the caller writes next. Worth stating plainly: " +
			"current Node and WSGI both reject control characters in header values, so on " +
			"those runtimes this is defence in depth rather than a live break -- it is " +
			"reported because the code is wrong wherever it is deployed, not because every " +
			"runtime still falls for it",
		By:       []string{"untrusted-to-header"},
		Subsumes: true,
	},
	"CWE-477": {State: Partial, Reason: "a function superseded for a reason that matters: createCipher derives its key with a single unsalted MD5 of the passphrase, so two applications sharing a passphrase share a key. The named functions only -- obsolete is a judgement about a specific API and not something a rule can infer",
		By: []string{"obsolete-function"}},
	"CWE-780": {State: Partial, Reason: "RSA encryption with PKCS#1 v1.5 padding, which has been known broken since 1998 and whose fix is a different padding rather than a different key. The named constructors only; a padding chosen through a variable is not matched",
		By: []string{"rsa-without-oaep"}},

	"CWE-807": {State: Partial, Reason: "a branch decided on a field the caller sent whose NAME says it is a privilege -- role, admin, permission, scope. The name is the whole evidence and it is used to narrow rather than to detect: the value must also be caller-supplied and must actually decide a comparison. A privilege read from an established session is not caller-supplied and is not reported",
		By: []string{"caller-decides-own-authority"}},
	"CWE-565": {State: Partial, Reason: "the same decision made on a COOKIE, which is its own weakness: a cookie is a value the browser was handed and hands back, and getting it back is no evidence it came from here or came back unchanged. Nothing is claimed about whether the cookie is signed, because a signed cookie and an unsigned one are read identically",
		By: []string{"cookie-decides-authority"}},

	"CWE-293": {State: Partial, Reason: "a branch decided on the Referer header, which says where a request came from only in the sense that it says whatever the sender wrote there. A browser sends it, a script omits it, and anything can forge it. Only a comparison; using the Referer to build a link is not this",
		By: []string{"referer-decides-access"}},
	"CWE-350": {State: Partial, Reason: "a branch decided on the result of a reverse DNS lookup, which returns whatever the owner of the address block published in the PTR record -- not evidence of who they are. The named lookup functions only",
		By: []string{"reverse-dns-decides-access"}},

	"CWE-117": {State: Partial, Reason: "untrusted data COMPOSED into a log line, where a line break lets the caller write entries of their own with whatever timestamp, level and actor they choose. Composition is required and is what makes the rule usable: a value logged whole is a field, and there are 11,164 log call sites across the clean corpus. Structured loggers that encode their fields are not modelled, so those report too",
		By: []string{"untrusted-to-log-line"}},

	// A written-down IV is a weak IV whatever the mode, so the rule that finds one is
	// this weakness and CWE-329 is the CBC-specific spelling of it. Asserted here and
	// separately below, because both are real identities for the same line.
	"CWE-1204": {
		State:    Partial,
		Reason:   "an initialisation vector written into the source, which is predictable by construction and reused on every message",
		By:       []string{"predictable-iv"},
		Subsumes: true,
	},

	"CWE-134": {State: Partial, Reason: "a format string the caller supplied, told apart from a format the application wrote by the RECEIVER: `\"Hello {}\".format(name)` is safe and `name.format(x)` is not. The call must also have been handed something, because a format with nothing to format has nothing to reach through",
		By: []string{"untrusted-as-format-string"}},

	// Subsumes CWE-313, which is this weakness with the storage named as a file -- and a
	// file is the only storage described, so the variant is exactly what the rule finds.
	"CWE-312": {
		State: Partial,
		Reason: "a credential the caller sent written to a file, where it outlives the " +
			"request that carried it and ends up in backups and images nobody thinks of " +
			"as holding secrets. Whether the application encrypts before writing is not " +
			"decidable from the call, so an encrypted write reports too",
		By:       []string{"credential-stored-cleartext"},
		Subsumes: true,
	},

	"CWE-501": {State: Partial, Reason: "a caller-asserted AUTHORITY written into the session, which everything downstream reads back as state the server established. Deliberately not caller input generally: sessions legitimately hold a return URL, a pending registration or a theme, and nodebb does exactly that twice. What must not cross is a claim about what the caller is allowed to do. Only the session is described as a destination, because the engine has no way to know where an application draws its other boundaries",
		By: []string{"untrusted-into-session"}},

	"CWE-760": {State: Partial, Reason: "a salt written into the source, which is the same salt for every password in the database -- the one thing a salt exists to prevent, because a single precomputed table then works against all of them. A salt read from a column or generated per password is not a literal and is not matched",
		By: []string{"predictable-salt"}},
	"CWE-759": {State: Partial, Reason: "a caller's password reaching a hash function that takes no salt -- hashlib's digests in Python, and in Node an update() on an object that came out of createHash. The whole-value requirement is the rule itself rather than a precision measure: sha256(password + salt) composes the password with something else, and something else is what a salt is. A salt mixed in inside a helper this engine cannot see through is a stated miss",
		By: []string{"credential-unsalted-hash"}},
	"CWE-331": {State: Partial, Reason: "a random value written to be shorter than 128 bits, reaching a cookie. Judged at the SINK and not at the call, because the call cannot answer it: written as a call shape it produced 77 findings across the clean corpus and every one was a unique suffix, a SQL parameter name, a colour, a temporary table name or a slug checked for collisions in a loop. A length computed at runtime is not a number written in the call and is not matched",
		By: []string{"short-secret"}},
	"CWE-337": {State: Partial, Reason: "the clock, the process id or a version 1 UUID reaching the argument a generator is seeded from. A seed decides every number that follows it, so a seed anybody can recompute is a sequence anybody can recompute. Only the generators this engine models are described as seedable",
		By: []string{"predictable-seed"}},
	"CWE-341": {State: Partial, Reason: "the same observable values reaching a cookie, which is the sink where unguessability is the whole point. Distinct from CWE-338 by WHAT the value came from: a fast random number is a different mistake from the current time, and both are judged at the sink rather than at the call. Signing ends it, because a signed token cannot be forged however public its fields are -- but only where the signing call is ON THE PATH: measured on the clean corpus two findings remain where the token is minted by the application's own helper and the engine cannot see the jwt.encode inside it",
		By: []string{"observable-secret"}},
	"CWE-552": {State: Partial, Reason: "a static file handler pointed at a directory that was never meant to be public -- the project root, the filesystem root, a home directory. Only a directory written as a literal in the call is matched: a path built at runtime is not decidable here and is not guessed at",
		By: []string{"world-readable-root"}},
	"CWE-494": {State: Partial, Reason: "a shell command that fetches something over the network and pipes it into an interpreter. Whoever can answer for that host chooses what this machine runs, and there is no signature to check because nothing was signed. Only a command written as a literal: a URL built at runtime is not read, and a download whose bytes are executed later by some other means is not seen at all",
		By: []string{"unverified-download"}},
	"CWE-776": {State: Partial, Reason: "an XML parser told to lift its own expansion limits with huge_tree. Narrow on purpose: this is the option that removes libxml2's guard, and the parsers whose defaults are unsafe are already reported under CWE-611 where the caller supplies the document. Nothing is claimed about parsers this engine has no model for",
		By: []string{"entity-expansion"}},
	"CWE-613": {State: Partial, Reason: "a credential cookie whose lifetime is written into the call and is longer than a month. Only cookies whose NAME says they carry a credential are asked about, because a year-long theme preference is a feature. Thresholds are per-rule rather than per-keyword, because express counts milliseconds and Flask counts seconds under names that look the same. A lifetime computed at runtime, and a server-side session store expiry, are not decidable here",
		By: []string{"long-lived-session"}},
	"CWE-1022": {State: Partial, Reason: "a window opened onto a named target with no third argument, which is where noopener would be -- the opened page keeps a live reference back through window.opener and can navigate the page behind it. Only the scripted form: markup written as a template string is text to this engine and its attributes are not read",
		By: []string{"opener-reachable"}},
	"CWE-1021": {State: Partial, Reason: "framing protection switched off by name in the call. Only an explicit disable: an application that never sets the header at all is not reported, because absence would have to be judged program-wide and the engine cannot see middleware it has no model for",
		By: []string{"frames-allowed"}},

	// Two weaknesses this engine finds and reports under a SIBLING'"'"'s number. Recorded as
	// not built rather than claimed, because a coverage map is read by someone looking
	// for findings carrying that identity, and none ever will.
	"CWE-256": {State: NotBuilt, Reason: "a password stored in plaintext. The credential-to-file rule finds exactly this and reports it as CWE-312, which is the broader identity for the same line; a separate password-only classification would report it twice"},
	"CWE-523": {State: NotBuilt, Reason: "credentials sent without transport protection. The cleartext-transmission rule finds exactly this and reports it as CWE-319, which is the same line under the identity that names the scheme rather than the payload"},

	// MEASURED AND DECLINED. Each of these was counted on the clean corpus before any rule
	// was written, and each turned out to describe ordinary code rather than a defect. The
	// numbers are kept because "we decided not to" is only an honest answer when it says
	// what the decision was based on.
	"CWE-390": {State: NotBuilt, Reason: "an error caught and nothing done about it. Counted first: the clean corpus holds 372 Python handlers whose entire body is `pass` and 596 empty JavaScript catch blocks, nearly all of them deliberate -- a cleanup that may fail, an optional parse, a cache miss. A rule matching the shape would report a thousand lines of working code, and nothing in the source distinguishes a swallowed failure from an ignored one"},
	"CWE-391": {State: NotBuilt, Reason: "the same measurement as CWE-390 and the same conclusion: what makes an unchecked error a weakness is what the program then does as though nothing had failed, and that is not in the handler"},
	"CWE-396": {State: NotBuilt, Reason: "a catch for a generic exception. The clean corpus contains 5001 `except Exception` and 22 bare `except:` clauses. Catching broadly at a request boundary is how a web application avoids returning a stack trace, so the shape is as often the right thing as the wrong one and the source does not say which"},
	"CWE-647": {State: NotBuilt, Reason: "an authorization decision made on a raw URL path, which /Admin, //admin, /admin/ and an encoded slash all defeat. Counted 162 equality comparisons against a path or url property across the clean corpus, and the overwhelming majority are routing rather than authorization -- skip this middleware for /health, choose a renderer for /embed. The engine cannot tell a route decision from an access decision, and reporting both would bury the second in the first"},
	"CWE-427": {State: Partial, Reason: "the caller's data written into an executable search path -- PATH, NODE_PATH, PYTHONPATH, LD_PRELOAD -- which decides which binary the next exec actually runs. Nothing about that exec looks wrong afterwards, which is the point. Only a write to one of those names is matched",
		By: []string{"untrusted-into-search-path"}},
	"CWE-444": {State: Partial, Reason: "a server configured to accept malformed requests, which is what lets it disagree with the proxy in front of it about where one request ends and the next begins. Only the explicit option; nothing is claimed about the proxy or about parser versions",
		By: []string{"lenient-http-parser"}},
	"CWE-789": {State: Partial, Reason: "a caller choosing how many bytes to reserve, which is a caller choosing when the process runs out of memory. Nothing is interpreted and nothing leaks -- the request simply asks for more than there is. A bounds check the application performs first is not modelled, so a guarded allocation reports too",
		By: []string{"untrusted-allocation-size"}},

	"CWE-250": {State: Partial, Reason: "a process asking for the superuser by calling setuid or seteuid with 0. A process running as root does everything as root, so any defect anywhere in it has the whole machine behind it. Zero occurrences across thirty-five repositories, so this is fixture-validated only -- which is stated rather than left for a reader to discover",
		By: []string{"unnecessary-privilege"}},

	"CWE-15": {State: Partial, Reason: "the caller's data written into the process environment, which is inherited by every process this one starts and is where libraries look for their own configuration. The search-path names are excluded because CWE-427 claims them at a granularity that says something sharper",
		By: []string{"untrusted-into-environment"}},
	"CWE-261": {State: Partial, Reason: "a password passed to a base64 encoder. Encoding is not hiding: it turns straight back into what went in, so whoever holds the result holds the password. The named encoders only",
		By: []string{"credential-encoded"}},
	"CWE-257": {State: Partial, Reason: "a password passed to a reversible cipher. Encryption is not hashing -- it is recoverable by design, which is what a stored password must never be. The named encryption APIs only; a cipher assembled through an object is not matched",
		By: []string{"credential-encrypted"}},

	"CWE-524": {State: Partial, Reason: "a credential the caller sent written to a cache, which outlives the request that filled it and is usually shared -- another process, another host, a service somebody else runs. Matched on the cache-shaped method names with a non-builtin receiver, so a language container is excluded and a store nobody named is a stated miss",
		By: []string{"credential-cached"}},
	"CWE-307": {State: Partial, Reason: "a missing throttle on an entry point whose PATH says credentials are presented there -- login, signin, token, otp. Unlimited attempts against a login is how a password gets guessed, so the general missing-throttle finding is narrowed to this identity where the path says so. Inferred from the population like every convention finding, so it informs rather than gates, and the path list is short on purpose: a longer one would start guessing",
		By: []string{"expectations"}},

	// Cookie attributes. Two of the three are claimed for an explicit downgrade AND for
	// an omission; Secure is claimed only for the downgrade, because the correct idiom
	// makes it conditional on the environment and a rule demanding a literal would report
	// every application that does the right thing.
	"CWE-1004": {State: Partial, Reason: "a credential-carrying cookie set with no httpOnly attribute, or with one written as false. Claimed only where the option keys were actually enumerated: options built in another function are unknowable and are passed over in silence, which is four sites in one production file. Which cookies carry credentials is decided by name, used to narrow an existing match rather than to make one, so the failure mode is a stated miss rather than a false alarm",
		By: []string{"cookie-not-http-only", "cookie-http-only-disabled"}},
	"CWE-614": {State: Partial, Reason: "a credential cookie with Secure explicitly disabled. Absence is deliberately not claimed: `secure: process.env.NODE_ENV === \"production\"` is correct and is not a literal",
		By: []string{"cookie-not-secure"}},
	"CWE-1275": {State: Partial, Reason: "a credential cookie with SameSite=None. Reported and never gating, because an embedded widget and an OAuth flow both legitimately need it and the call does not carry which case this is",
		By: []string{"cookie-same-site-none"}},

	// Real, and about something no analysis of source can see.
	"CWE-285":  {State: Undecidable, Reason: "the intended entitlements are not in the code; a declared policy is what supplies them (ADR-011)"},
	"CWE-1104": {State: Undecidable, Reason: "whether a dependency is maintained is a fact about the world, not about this source"},
}

// claimFor returns what the engine says about a weakness, defaulting from the catalog.
func claimFor(w Weakness) Claim {
	if c, ok := claims[w.ID]; ok {
		return c
	}
	switch {
	case w.Status == "Deprecated":
		return Claim{State: OutOfScope, Reason: "withdrawn from the catalog"}
	case !w.HasCodeShape():
		return Claim{State: Abstract, Reason: "a " + strings.ToLower(w.Abstraction) +
			", covered by covering the weaknesses beneath it rather than directly"}
	case !w.StaticDetectable:
		return Claim{State: Undecidable,
			Reason: "the catalog records no static-analysis detection method for it"}
	case !w.LanguageAgnostic && !ours(w.Languages):
		return Claim{State: OutOfScope,
			Reason: "specific to a language this engine has no frontend for"}
	}
	if parent, ok := subsumingAncestor(w); ok {
		return Claim{
			State: Subsumed,
			Reason: "a more specific form of " + parent.ID + " (" + parent.Name +
				"), which is asserted, and the detail that distinguishes it is one the " +
				"analysis never looks at",
			By: claims[parent.ID].By,
		}
	}
	// The default reason, derived rather than repeated.
	//
	// "No rule has been written for it" is true of two hundred entries and tells a reader
	// nothing about which of them are worth writing next. The catalog already knows which
	// languages a weakness applies to, so where those do not include the ones this engine
	// reads, the reason can say so and name them.
	//
	// The STATE stays not-built rather than out-of-scope, deliberately. Out-of-scope
	// removes an entry from the denominator, and a denominator that shrinks whenever
	// something looks hard is not a denominator anybody should trust. These stay counted
	// and are simply honest about why nobody has written them.
	if !w.LanguageAgnostic && len(w.Languages) > 0 && !analysed(w.Languages) {
		return Claim{State: NotBuilt, Reason: "the catalog lists this as applying to " +
			strings.Join(w.Languages, ", ") + ", and this engine reads JavaScript, " +
			"TypeScript and Python; a rule would have to wait for a frontend that reads one of those"}
	}
	return Claim{State: NotBuilt, Reason: "no rule has been written for it"}
}

// analysed reports whether any of these languages is one the engine actually reads today.
// Distinct from ours(), which is the wider set the denominator is drawn from: a weakness
// specific to a language nobody has a frontend for is still counted, and this is only
// about what its reason should say.
func analysed(langs []string) bool {
	for _, l := range langs {
		switch l {
		case "JavaScript", "TypeScript", "Python":
			return true
		}
	}
	return false
}

// subsumingAncestor walks up the catalog's own ChildOf relationships for a claim that
// says it covers everything beneath it.
//
// Transitive because the catalog nests: `Path Traversal: '../filedir'` is a child of
// `Relative Path Traversal`, which is a child of `Path Traversal`, and only the last of
// those three has a rule. Depth is bounded and cycles are guarded because a published
// taxonomy is not something this engine gets to assume is acyclic.
func subsumingAncestor(w Weakness) (Weakness, bool) {
	seen := map[string]bool{w.ID: true}
	queue := append([]string(nil), w.ChildOf...)
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		parent, ok := byID(id)
		if !ok {
			continue
		}
		if c, ok := claims[id]; ok && c.Subsumes {
			return parent, true
		}
		queue = append(queue, parent.ChildOf...)
	}
	return Weakness{}, false
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
