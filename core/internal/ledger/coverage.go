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
		By: []string{"disabled-certificate-check"},
		// Turning verification off turns off everything verification does: following the
		// chain to a root, and asking whether the certificate was revoked. The analysis
		// sees the option and never asks which sub-check the caller had in mind, so the
		// variants beneath this are the same line under narrower names.
		Subsumes: true},
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
	"CWE-347": {State: Partial, Reason: "signature verification switched OFF by name in the call, including where the option sits inside a nested dict -- PyJWT's options={\"verify_signature\": False} was a stated miss until options one level down were read, and it is where four of the seven clean-corpus findings turned out to be. Matching decode() itself was tried and withdrawn: reading a token to look at it is ordinary and 58 sites across the clean corpus do exactly that. Reported and never gating for the same reason at one remove -- capping an expiry or routing on an issuer needs no verification, and what makes an unverified decode a defect is whether the claims are then believed, which the call does not carry",
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
	"CWE-749": {State: Partial, Reason: "a desktop shell window told to give page content the runtime -- node integration on, context isolation off, the remote module enabled. Named by OPTION rather than by callee, because these names mean one thing wherever they appear and enumerating the wrappers that pass them through would be wrong the moment somebody wrote another one. Nothing is claimed about methods a program exposes over its own IPC, which is the same weakness and is not decidable from a name",
		By: []string{"renderer-has-runtime"}},
	"CWE-778": {State: NotBuilt, Reason: "an entry point that records nothing about what happened. Counted first: 3 of 6390 entry points across the clean corpus apply a route-scoped middleware whose name mentions logging, auditing or tracking, so the population this engine infers expectations from has nothing to say -- a convention rule needs peers that agree, and here there are none. Application-wide logging middleware, which is how it is actually done, applies to every route equally and can never produce a deviation. Measured a second way as well, in case the convention engine was the wrong tool: of 180 entry points whose PATH says credentials are presented there, 169 call nothing resembling a log inside the handler, because the logging happens in a service layer the handler calls. Both measurements say the same thing"},
	"CWE-606": {State: NotBuilt, Reason: "a loop bound the caller chose. Counted 0 across the clean corpus under the shape a rule could match, and the reason is structural rather than lucky: a request value has to be turned into a number before it can bound a loop, and int() and Number() are one-way transforms that end the classification -- correctly, since a number cannot carry syntax. What is left is a magnitude question the engine does not model. The allocation half of this is claimed under CWE-789"},
	"CWE-759": {State: Partial, Reason: "a caller's password reaching a hash function that takes no salt -- hashlib's digests in Python, and in Node an update() on an object that came out of createHash. The whole-value requirement is the rule itself rather than a precision measure: sha256(password + salt) composes the password with something else, and something else is what a salt is. A salt mixed in inside a helper this engine cannot see through is a stated miss",
		By: []string{"credential-unsalted-hash"}},
	"CWE-331": {State: Partial, Reason: "a random value written to be shorter than 128 bits, reaching a cookie. Judged at the SINK and not at the call, because the call cannot answer it: written as a call shape it produced 77 findings across the clean corpus and every one was a unique suffix, a SQL parameter name, a colour, a temporary table name or a slug checked for collisions in a loop. A length computed at runtime is not a number written in the call and is not matched",
		By: []string{"short-secret"}},
	"CWE-337": {State: Partial, Reason: "the clock, the process id or a version 1 UUID reaching the argument a generator is seeded from. A seed decides every number that follows it, so a seed anybody can recompute is a sequence anybody can recompute. Only the generators this engine models are described as seedable",
		By: []string{"predictable-seed"}},
	"CWE-341": {State: Partial, Reason: "the same observable values reaching a cookie, which is the sink where unguessability is the whole point. Distinct from CWE-338 by WHAT the value came from: a fast random number is a different mistake from the current time, and both are judged at the sink rather than at the call. Signing ends it, because a signed token cannot be forged however public its fields are -- but only where the signing call is ON THE PATH: measured on the clean corpus two findings remain where the token is minted by the application's own helper and the engine cannot see the jwt.encode inside it",
		By: []string{"observable-secret"}},
	"CWE-521": {State: Partial, Reason: "a caller's password measured against a number written in the source and admitted below eight characters. The number is the whole rule rather than the shape: len(password) > 72 is bcrypt's maximum and the identical comparison read the other way, and a minimum read from configuration is a threshold the source does not contain and is a stated miss. Nothing is claimed about complexity requirements, dictionaries or reuse",
		By: []string{"weak-password-policy"}},
	"CWE-552": {State: Partial, Reason: "a static file handler pointed at a directory that was never meant to be public -- the project root, the filesystem root, a home directory. Only a directory written as a literal in the call is matched: a path built at runtime is not decidable here and is not guessed at",
		By: []string{"world-readable-root"},
		// What a served directory exposes depends on what is IN it, and the rule never
		// looks: a core dump and a database backup in the project root are the same
		// finding at the same line, under narrower names.
		Subsumes: true},
	// The catalog records no static-analysis detection method for this one, which is
	// where an entry would normally stop. Disagreeing with it deliberately: there IS a
	// decidable form -- a secret compared with the language equality operator rather than
	// with a constant-time compare -- and saying so is more useful than deferring to a
	// field that was written about the weakness in general.
	"CWE-183": {State: Partial, Reason: "an origin or a referrer checked against an allow-list by prefix, suffix or containment rather than by equality. The list is right and the comparison is too generous, which is the harder half to see: a prefix match accepts https://example.com.attacker.net and a suffix match accepts https://notexample.com, and both pass a check that reads as correct. Only where the string being matched is one the caller SENT, which the dataflow already answers; an allow-list checked against something else is not this weakness. Clean corpus: zero",
		By: []string{"permissive-origin-match"}},
	"CWE-208": {State: Partial, Reason: "a value the caller sent as a credential compared with the language's equality operator. Neither language promises constant-time comparison and neither implementation delivers it, so the time taken says how much of the guess was right. The other side must be a RUNTIME value: comparing a token to a literal is a presence check, a flag test, or a hardcoded credential, and the last of those is CWE-798. The correct fix is a constant-time compare, which is a call and leaves no comparison to match, so a fixed program is silent. Two further conditions came from measuring: a field read OFF something the credential produced is not the credential (`session.tenantId` is a tenant id), and two values the same caller just sent compared against each other are a confirmation field rather than a secret check. Clean corpus: two findings, both real",
		By: []string{"credential-compared-in-variable-time"}},
	// A second deliberate disagreement with the catalog, which records no static
	// detection method and tags the weakness "Other". Both are about the weakness in
	// general; the form here -- an address written into a bind call -- is as decidable as
	// anything in this file.
	"CWE-1327": {State: Partial, Reason: "a server told to listen on every address the host has. On a laptop that is a demo; on a host with a second interface, a container in host-network mode, or a cloud instance with a public address, it is the difference between a service the application can reach and a service anybody can. Only an address written into the call: a host read from configuration is the correct way to do this and is not a literal. Measured across the clean corpus this matches once, in an end-to-end test helper",
		By: []string{"bound-to-every-interface"}},
	"CWE-323": {State: Partial, Reason: "an initialisation vector bound at MODULE scope, which is computed once when the file loads and reused for every message the process encrypts. Distinct from a literal IV, which CWE-1204 and CWE-329 already read: this is the version with no literal to read, and it looks correct at a glance because a random number was involved. Asks where the argument was bound rather than what it says, and only a direct reference counts -- following it through assignments would answer a question about the value's history instead of about where it lives",
		By: []string{"reused-iv"}},
	"CWE-359": {State: Partial, Reason: "a fact about a person that cannot be reissued -- a national identity number, a date of birth, a medical record -- reaching a log or a third party. Its own classification rather than more credentials, because a password gets rotated after it leaks and this does not. The vocabulary is short and specific: these names appear three times across 28 production repositories and two of those three are Passport, the authentication library, which is why the bare word is not on the list. A field this engine has no name for is a stated miss",
		By: []string{"personal-information-logged", "personal-information-sent"}},
	"CWE-488": {State: Partial, Reason: "one request's data assigned to a name bound outside the handler, which every later request reads back. The language rule is the whole evidence and there is no guessing in it: Python needs the name declared global and JavaScript needs it bound in an enclosing scope, and the same statement without either makes a local and touches nothing. A value stored in a module-level CONTAINER -- a dict, a Map -- is a cache and is not matched",
		By: []string{"request-data-into-process-state"}},
	"CWE-472": {State: Partial, Reason: "a field naming a privilege -- role, isAdmin, permissions, scopes -- assigned from data the caller sent. The rule names the FIELD and says nothing about the object holding it, because `user.role = req.body.role` and `account.isAdmin = req.body.isAdmin` are the same weakness on two records and enumerating what a record can be called would be a list that goes wrong immediately. Distinct from mass assignment, where the caller supplies keys nobody enumerated: here the application enumerated one and picked the wrong one. Counted 22 sites across the clean corpus that mention a privilege field and none of them is a write, so a privilege PASSED to a service constructor is a stated miss",
		By: []string{"caller-sets-own-privilege"}},
	"CWE-494": {State: Partial, Reason: "a shell command that fetches something over the network and pipes it into an interpreter. Whoever can answer for that host chooses what this machine runs, and there is no signature to check because nothing was signed. Only a command written as a literal: a URL built at runtime is not read, and a download whose bytes are executed later by some other means is not seen at all",
		By: []string{"unverified-download"}},
	"CWE-776": {State: Partial, Reason: "an XML parser told to lift its own expansion limits with huge_tree. Narrow on purpose: this is the option that removes libxml2's guard, and the parsers whose defaults are unsafe are already reported under CWE-611 where the caller supplies the document. Nothing is claimed about parsers this engine has no model for",
		By: []string{"entity-expansion"}},
	"CWE-597": {State: Partial, Reason: "a string compared by IDENTITY rather than by value. Python interns some strings and not others, so the answer depends on how the value was built rather than on what it says, and the check silently stops working the day the string arrives from somewhere else. The only rule here that names no classification: the defect is in the comparison itself, whatever is being compared. Numbers are excluded because small integers ARE interned and `x is 5` is a different question",
		By: []string{"identity-compared-to-text"}},
	"CWE-1389": {State: Partial, Reason: "a number parsed with the base left to the text. Radix zero means infer, so a caller who sends 0x10 gets sixteen from a field meant to hold ten. Deliberately NOT justified by the leading-zero octal reading, which ES5 removed. Only the explicit zero is matched: an omitted radix behaves the same way and has the same defect, and reporting it would report most of the JavaScript ever written",
		By: []string{"inferred-radix"}},
	"CWE-613": {State: Partial, Reason: "a credential cookie whose lifetime is written into the call and is longer than a month. Only cookies whose NAME says they carry a credential are asked about, because a year-long theme preference is a feature. Thresholds are per-rule rather than per-keyword, because express counts milliseconds and Flask counts seconds under names that look the same. A lifetime computed at runtime, and a server-side session store expiry, are not decidable here",
		By: []string{"long-lived-session", "unexpiring-token"}},
	"CWE-1022": {State: Partial, Reason: "a window opened onto a named target with no third argument, which is where noopener would be -- the opened page keeps a live reference back through window.opener and can navigate the page behind it. Only the scripted form: markup written as a template string is text to this engine and its attributes are not read",
		By: []string{"opener-reachable"}},
	"CWE-1021": {State: Partial, Reason: "framing protection switched off by name in the call. Only an explicit disable: an application that never sets the header at all is not reported, because absence would have to be judged program-wide and the engine cannot see middleware it has no model for",
		By: []string{"frames-allowed"}},

	// Two weaknesses this engine finds and reports under a SIBLING'"'"'s number. Recorded as
	// not built rather than claimed, because a coverage map is read by someone looking
	// for findings carrying that identity, and none ever will.
	"CWE-256": {State: NotBuilt, Reason: "a password stored in plaintext. The credential-to-file rule finds exactly this and reports it as CWE-312, which is the broader identity for the same line; a separate password-only classification would report it twice"},
	"CWE-523": {State: NotBuilt, Reason: "credentials sent without transport protection. The cleartext-transmission rule finds exactly this and reports it as CWE-319, which is the same line under the identity that names the scheme rather than the payload"},

	// CONSIDERED AND DECLINED for a reason that is not a measurement: either another
	// number already carries the finding, or the evidence the weakness turns on is not in
	// the source at all.
	"CWE-838":  {State: NotBuilt, Reason: "a value escaped for the wrong context -- URL-encoded and then written into markup. The engine already knows this: a transform that does not clear the sink's context is recorded in the evidence with clears=false, and the finding is reported under the identity of the weakness the transform FAILED to prevent, which for markup is CWE-79. Reporting it under this number instead would trade a name the reader can act on for one that describes the mechanism"},
	"CWE-829":  {State: NotBuilt, Reason: "functionality included from somewhere the application does not control. This engine finds two specific forms and reports each under its own number: the caller naming a module for the runtime to load is CWE-470, and code fetched over the network and piped into an interpreter is CWE-494. The parent adds no line either of those misses"},
	"CWE-96":   {State: NotBuilt, Reason: "caller data written into a file that is later executed as code. Two artifacts and two moments: the write is here and the execution is elsewhere, usually in another process and often in another language, and nothing in one source tree links them. What IS decidable -- data reaching an interpreter directly -- is CWE-95"},
	"CWE-215":  {State: NotBuilt, Reason: "sensitive information in debugging code. Both halves are already claimed and reported: a credential or system fact reaching a log is CWE-532 and CWE-497, and a debug server started with debug enabled is CWE-489. What this number adds is the judgement that the code was DEBUG code, and a logger called debug is not evidence of that -- production systems log at debug level on purpose"},
	"CWE-1295": {State: NotBuilt, Reason: "the same shape as CWE-215 and the same answer: what reaches the message is claimed under CWE-209 and CWE-497, and whether the message was unnecessarily detailed is a judgement about intent"},
	"CWE-212":  {State: NotBuilt, Reason: "sensitive information not removed before something is stored or sent. The engine reports what it can SEE reaching a destination -- CWE-201 for sent data, CWE-312 for stored -- and this number is about what should have been taken out, which requires knowing what the record was supposed to contain"},
	"CWE-535":  {State: NotBuilt, Reason: "a shell error message exposed. The failure detail rule finds this where the message reaches a caller and reports it as CWE-209, which is the same line under the identity that names the exposure rather than the source of the text"},
	"CWE-379":  {State: NotBuilt, Reason: "a temporary file created in a directory anyone can write to. The insecure-temp-file rule finds the calls that make one and reports them as CWE-378, its sibling; what would distinguish this is the directory's permissions, which are a fact about the machine rather than about the source"},
	"CWE-540":  {State: NotBuilt, Reason: "sensitive information in source code. Its one decidable form -- a credential written into the source -- is CWE-798, and this engine reports 27 of them across the clean corpus under that number. What is left is internal hostnames, paths and comments, where nothing in the text says whether publishing it matters"},
	"CWE-626":  {State: NotBuilt, Reason: "a null byte truncating a path or a name. Both frontends target runtimes that reject an interior null in a path outright -- Node throws, Python raises -- so the interpretation this weakness depends on does not happen"},
	"CWE-332":  {State: NotBuilt, Reason: "insufficient entropy in a PRNG specifically. The rule this engine has asks whether a random value was long enough and does not ask what produced it beyond the symbol, so a generator that is weak for a reason other than its length is not seen. Its sibling CWE-338 covers the generator being the wrong KIND"},
	"CWE-546":  {State: NotBuilt, Reason: "a comment that admits something. Comments are not in the IR at all -- the frontends lower code -- and a TODO is a note about work rather than a defect in it"},
	"CWE-615":  {State: NotBuilt, Reason: "sensitive information in a comment. Same reason as CWE-546: comments are not lowered, and adding them would mean matching secrets in prose, which is the least reliable rule this project could ship"},
	"CWE-625":  {State: NotBuilt, Reason: "a regular expression that permits more than it should -- typically one missing its anchors. The engine cannot tell a validating match from a searching one, and an unanchored pattern is exactly right for the second: a rule would report every search in the corpus to catch the occasional check"},
	"CWE-367":  {State: NotBuilt, Reason: "a check and a use separated in time. The shape is visible -- exists() then open() on the same path -- and what makes it a weakness is not: whether anything else can write that path between the two calls is a fact about the filesystem and the other programs on the machine"},

	// MEASURED AND DECLINED. Each of these was counted on the clean corpus before any rule
	// was written, and each turned out to describe ordinary code rather than a defect. The
	// numbers are kept because "we decided not to" is only an honest answer when it says
	// what the decision was based on.
	"CWE-617":  {State: NotBuilt, Reason: "an assertion an attacker can reach, which in Python is also an assertion that disappears under -O. Counted 2695 assert statements across 361 non-test files in the clean corpus, nearly all of them invariants somebody wanted checked during development. The narrow form worth having -- an assert that performs an authorization check -- would need the IR to record assertions at all, and would then have to tell a security check from an invariant, which the statement does not say"},
	"CWE-1088": {State: NotBuilt, Reason: "an outbound request with no timeout, which waits for as long as the far end cares to keep it waiting. Decidable and measured: 79 of the 142 outbound calls across the clean corpus pass no timeout, which is five production applications behaving the same way. Reporting it would double this engine's output to say something every one of them has already decided to live with, and nothing in the source distinguishes an oversight from that decision"},
	"CWE-390":  {State: NotBuilt, Reason: "an error caught and nothing done about it. Counted first: the clean corpus holds 372 Python handlers whose entire body is `pass` and 596 empty JavaScript catch blocks, nearly all of them deliberate -- a cleanup that may fail, an optional parse, a cache miss. A rule matching the shape would report a thousand lines of working code, and nothing in the source distinguishes a swallowed failure from an ignored one"},
	"CWE-391":  {State: NotBuilt, Reason: "the same measurement as CWE-390 and the same conclusion: what makes an unchecked error a weakness is what the program then does as though nothing had failed, and that is not in the handler"},
	"CWE-396":  {State: NotBuilt, Reason: "a catch for a generic exception. The clean corpus contains 5001 `except Exception` and 22 bare `except:` clauses. Catching broadly at a request boundary is how a web application avoids returning a stack trace, so the shape is as often the right thing as the wrong one and the source does not say which"},
	"CWE-647":  {State: NotBuilt, Reason: "an authorization decision made on a raw URL path, which /Admin, //admin, /admin/ and an encoded slash all defeat. Counted 162 equality comparisons against a path or url property across the clean corpus, and the overwhelming majority are routing rather than authorization -- skip this middleware for /health, choose a renderer for /embed. The engine cannot tell a route decision from an access decision, and reporting both would bury the second in the first"},
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

// Grouped reasons.
//
// A hundred and twenty entries once said "no rule has been written for it", which is true
// of all of them and useful about none: a reader deciding what to build next learns
// nothing from a sentence that does not distinguish a weakness this engine could catch
// tomorrow from one no analysis of source will ever decide.
//
// These are grouped rather than repeated, because the reason really is shared -- what
// makes a data race undecidable here is the same fact about both runtimes for every data
// race -- and writing it once means it can be corrected once.
func init() {
	for _, g := range groupedReasons {
		for _, id := range g.ids {
			if _, taken := claims[id]; taken {
				continue
			}
			claims[id] = Claim{State: NotBuilt, Reason: g.reason}
		}
	}
}

var groupedReasons = []struct {
	reason string
	ids    []string
}{
	{
		reason: "a concurrency defect. Both runtimes this engine reads make the shape it would look for meaningless: JavaScript runs one event loop per process and Python holds a global lock, so two statements in one source file do not interleave the way this weakness assumes. The races these applications really have are between PROCESSES -- two workers reading the same row, two containers claiming the same job -- and nothing in one source tree shows a second process",
		ids: []string{"CWE-363", "CWE-366", "CWE-368", "CWE-413", "CWE-414", "CWE-543",
			"CWE-567", "CWE-609", "CWE-663", "CWE-764", "CWE-765", "CWE-821", "CWE-828",
			"CWE-832", "CWE-833", "CWE-1341"},
	},
	{
		reason: "a resource-lifetime defect. Both runtimes collect memory automatically, so the memory half of this cannot happen; the handle half can, and the shape that would find it -- a file opened outside a context manager, a connection never closed -- is how a great deal of correct code is written, because the handle is closed by the object going out of scope. What distinguishes a leak from that is how long the object lives, which is a runtime fact",
		ids: []string{"CWE-401", "CWE-403", "CWE-459", "CWE-771", "CWE-772", "CWE-773",
			"CWE-774", "CWE-775", "CWE-826", "CWE-908", "CWE-910"},
	},
	{
		reason: "a numeric-representation defect. JavaScript has one number type and Python has arbitrary-precision integers, so wraparound does not occur in either. What IS real -- JavaScript losing precision above 2^53, a float compared for equality -- turns on the MAGNITUDE of values the source does not contain",
		ids: []string{"CWE-190", "CWE-191", "CWE-192", "CWE-193", "CWE-197", "CWE-369",
			"CWE-681", "CWE-1024", "CWE-1077", "CWE-1335", "CWE-1339"},
	},
	{
		reason: "a maintainability property rather than a weakness. This engine reports defects an attacker can reach, and a long file, a complex function, a redundant branch or a dead assignment is none of those. A linter measures these well and this is not one",
		ids: []string{"CWE-474", "CWE-475", "CWE-478", "CWE-480", "CWE-484", "CWE-561",
			"CWE-563", "CWE-570", "CWE-571", "CWE-584", "CWE-589", "CWE-595",
			"CWE-687", "CWE-768", "CWE-783", "CWE-835", "CWE-1025", "CWE-1041", "CWE-1055",
			"CWE-1056", "CWE-1064", "CWE-1071", "CWE-1075", "CWE-1079", "CWE-1080",
			"CWE-1085", "CWE-1099", "CWE-1105", "CWE-1106", "CWE-1108", "CWE-1121",
			"CWE-1126", "CWE-1235"},
	},
	{
		reason: "specific to a platform this engine has no frontend for -- an Android application, a browser control, or silicon. The catalog does not mark these as language-specific because the weakness is about the platform rather than the language, so they are not filtered out automatically; they are still unreachable from a JavaScript or Python source tree",
		ids: []string{"CWE-618", "CWE-695", "CWE-925", "CWE-926", "CWE-927", "CWE-939",
			"CWE-1316", "CWE-1318", "CWE-1332", "CWE-1420", "CWE-1422", "CWE-1429", "CWE-1431"},
	},
	{
		reason: "a fact about the running system rather than about the source. What privileges a process actually holds, what a deployment sets, which port is already bound, what a file's permissions are on the machine -- none of it is written in the code, and a rule reading the code would be guessing at it",
		ids: []string{"CWE-226", "CWE-272", "CWE-273", "CWE-274", "CWE-279", "CWE-280",
			"CWE-403", "CWE-453", "CWE-456", "CWE-457", "CWE-510", "CWE-511", "CWE-605",
			"CWE-1188"},
	},
	{
		reason: "a protocol or format the engine models no vocabulary for. Each would need the shape of a correct exchange written down -- which steps an authentication has, what a schema validates, what a nonce may not be reused across -- and this project builds a rule only where the source itself carries the answer",
		ids: []string{"CWE-91", "CWE-112", "CWE-130", "CWE-150", "CWE-155", "CWE-182",
			"CWE-183", "CWE-233", "CWE-289", "CWE-304", "CWE-322", "CWE-325",
			"CWE-335", "CWE-394", "CWE-397", "CWE-474", "CWE-549", "CWE-1173"},
	},
	{
		reason: "a path-interpretation defect: two spellings of one location, or a link that points somewhere else. This engine reports the caller CONTROLLING a path (CWE-22 and CWE-73) and never inspects the path's CONTENTS, which is what would distinguish these -- and the answer depends on the filesystem the code is running on rather than on the code",
		ids:    []string{"CWE-41", "CWE-59", "CWE-66"},
	},
	{
		reason: "a bound the caller chose, used as an index, a length or a limit. Structurally out of reach rather than merely unbuilt: a request value has to become a NUMBER before it can be one of those, and the numeric conversions are one-way transforms that end the classification -- correctly, since a number cannot carry syntax. What remains is a question about magnitude, which this engine does not model. The allocation form is claimed under CWE-789",
		ids:    []string{"CWE-129", "CWE-1284", "CWE-1285"},
	},
	{
		reason: "an unchecked or misread return value. Both runtimes signal failure by raising rather than by returning a code, so the shape this weakness describes -- a status nobody looked at -- is not how errors travel here. A discarded promise is the real local form of it and is a correctness question rather than a security one",
		ids:    []string{"CWE-252", "CWE-253"},
	},
	{
		reason: "a TRUSTED module-level variable initialised from outside. The caller's data reaching process-wide state is claimed under CWE-488; what this number adds is the judgement that the variable was one the program later trusts, and the source does not say which module-level variables those are",
		ids:    []string{"CWE-454"},
	},
	{
		reason: "a secret or a security-relevant constant living somewhere this engine does not read. Configuration files, environment templates and deployment manifests are not source and are not lowered; what IS in the source is claimed under CWE-798 and CWE-321",
		ids:    []string{"CWE-260", "CWE-547"},
	},
	{
		reason: "information written somewhere it can be reached from outside. The engine reports what it can watch data REACH -- a log, a response, a cache, a third party -- and this asks instead whether the destination is externally reachable, which is a deployment fact: whether that directory is served, whether that bucket is public, whether that path is behind the proxy",
		ids:    []string{"CWE-538", "CWE-779"},
	},
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
