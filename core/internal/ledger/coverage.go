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
// Every claim below rests on the enumerated surface (ADR-009), and the surface stopped
// being all HTTP routes. Four classes of entry point are enumerated, each with its own
// trust label, and what a claim COVERS follows from which of them can reach the code:
//
//   - http-route     (remote)   what a caller outside the process can reach.
//   - cli-command    (operator) a Django management command's `handle`, whose sources are
//     the parameters argparse fills in from what a person typed.
//   - process-start  (operator) the top level of a module the LANGUAGE designates as a
//     program start -- a `__main__` guard, or a package's `__main__.py` -- whose sources
//     are the environment and the configuration it was started with.
//   - scheduled-job / event-consumer (internal) a callback a timer or an in-process bus
//     runs, whose sources are the data the program PERSISTED, reached through the store
//     model rather than through any request.
//
// Trust travels with the SOURCE and not with the sink, which is the only reading that
// survives a second-order flow: a cron job reading a column an HTTP request wrote is
// carrying a remote caller's value and gates, while a management command interpolating
// its own argument into a shell does not. That is what keeps the two apart in a report --
// a finding must be able to say "runs with operator privileges, not reachable by a remote
// caller", and ranking them together would misstate one of them.
//
// A background entry point must NAME ITS CALLBACK, which is the one place these differ
// from a route and is not a lapse from ADR-009. A route exists at an ADDRESS whether or
// not its handler resolves, so dropping it would hide surface; a job has no address -- it
// IS its callback -- so a row naming no function contributes no reachability and cannot be
// reasoned about. Measured: allowing an unresolved argument through produced five entry
// points across ten repositories and every one was wrong, two of them an application's own
// method that happens to be spelled `schedule` and takes a record.
//
// Build and development machinery is enumerated and held OUT of the application's count,
// on the same terms as an example: `ir.Tooling`. A `setInterval` in a dev-watch script and
// a `__main__` guard in a release script are real and are not something the deployed
// application does. It matters at scale -- 15 of yt-dlp's 16 program starts are
// `devscripts/` and `bundle/`, leaving its actual entry point, `yt_dlp/__main__.py`, alone
// in a surface that had been empty.
//
// Measured, and the number is unflattering in the direction that matters: these classes
// added 134 entry points to the application surface of ten production repositories, and 26
// more held outside it -- 34 scheduled jobs and 25 bus consumers in one, 17 management
// commands in another -- and changed NOT ONE finding. What they bought on real code is
// reachability and an enumeration that names work the surface previously denied existed;
// the findings they make possible are asserted by fixture and have not yet been observed
// in the wild.
//
// --- three questions about how a value MOVES ------------------------------------------
//
// One propagation direction, one source family, and one label. All three were measured
// over the same ten production repositories before they landed, and the numbers are below
// because two of them are small and one of them is zero.
//
// A PROMISE CARRIES ITS VALUE OUT. A CallbackRule carried a class from a receiver INTO a
// callback's parameter, which is how `.forEach` and `.then` work and is the wrong
// direction for the construct Node is actually built out of. `new Promise(resolve => ...)`
// discards its executor's return value, and everything the promise will ever carry was
// handed to a continuation -- routinely from a callback several frames deeper, since
// bridging a callback API is the reason to write `new Promise` by hand at all. So every
// value computed inside an executor was invisible to every classification, and the helper
// that computed it read as a clean wrapper. This is a DIRECTION rather than a rule, so it
// was measured on all corpora and all ten repositories rather than on the one that
// produced it: it changed exactly one finding anywhere, pdfjs `test/downloadutils.mjs`:110
// -- an MD5 computed in a `stream.on("end", ...)` handler, resolved, awaited, and compared
// against a recorded digest. That is the first time the weak-digest rule has fired on
// anything outside a fixture, and the entry that asked for this said so in those words.
// The continuation is bound by NAME, to a parameter of a specific executor, within that
// executor's own call graph and unshadowed; a call the frontend resolved is a different
// function that happens to share the name and is not matched.
//
//	NOT CAUGHT: `reject`, deliberately -- a rejected value arrives at a catch handler
//	through control flow the IR does not carry, and delivering it to the await's result
//	would be wrong about where the value went rather than merely incomplete. Nor a
//	promise built by a wrapper (`util.promisify`, a deferred object) instead of by the
//	constructor, nor a continuation stored in a variable and called from a function the
//	executor's call graph does not reach.
//
// A RESPONSE IS TEXT SOMEBODY ELSE WROTE. Only request-derived values were sources, so an
// application parsing an upstream service's answer was parsing somebody else's bytes and
// the engine saw a clean local value. `upstream-response` is a class of its own rather
// than more request taint, for the reason the stored class is: what makes it worth
// reporting differs. A request is sent by a stranger and this is not necessarily -- an
// application routinely calls a service it operates itself -- and the engine cannot read a
// URL and say whose host it names. It therefore declines to guess and narrows the DENIED
// SET instead, and the narrowing was measured rather than assumed. Widened experimentally
// to every context the first-order class denies, it added nine findings to pdfjs (a
// `console.warn`, two build scripts that download Mozilla's translations, vendored WASM
// glue), one to linkwarden (a Content-Type echoed from a favicon service) and one to
// uptime-kuma (an axios result reaching `console.log`) -- every one of which turns on
// whose service it was. It also added eight to searxng, all
// `lxml.etree.fromstring(resp.content)` in engine modules, which do not: this model
// ALREADY asserts that pairing for a document a caller sent, on the grounds that lxml's
// default parser expands entities and the call supplied no parser of its own, and a parser
// does not care who wrote what it was handed. So the shipped set is the interpreter
// contexts plus the XML parser, minus LDAP, and the eight searxng findings are the whole
// of what this family produces on production code today.
//
//	  LDAP is subtracted for a reason worth writing down, because it is about a channel
//	  rather than about this class: the LDAP filter channel matches the METHOD NAME `search`
//	  on a receiver it requires to be external, and a frontend that cannot type receivers
//	  leaves that unanswerable -- correctly not the same as "not builtin" -- so in Python
//	  `re.search(pattern, url)` matches it at reduced confidence. That produced the one
//	  wrong finding this family made anywhere, yt-dlp `extractor/common.py`:2686, and it was
//	  wrong about the SINK and not about the source. Pairing a second class with a channel
//	  that already misreads a stdlib call multiplies a known imprecision, so an upstream
//	  response reaching a real LDAP filter is a stated miss until that channel can tell `re`
//	  from a directory connection.
//
//		It does not contradict the client-role judgement. That rule says a key this program
//		PRESENTS to a third party is that party's public configuration and not this program's
//		secret; this one says the answer that party sends BACK is that party's text. Both rest
//		on the third party being outside the trust boundary, and no value is ever both --
//		`testdata/upstream-response` holds both directions of one call and asserts both.
//		NOT CAUGHT: an application's OWN wrapper around its HTTP client. yt-dlp routes every
//		one of its ~7,900 extractors through `self._download_webpage` and
//		`self._download_json`, 1,354 call sites of two methods that exist only in that
//		program, and nothing in a policy document can currently tell the model about them --
//		which is the missing capability, not the missing names. The stdlib and the four
//		common clients are declared, and `urlopen` is matched on its last segment because
//		every spelling of it opens a URL. Also not caught: the second family the entry named,
//		a value read out of a PARSED DOCUMENT -- a PDF dictionary accessor, a deserializer
//		applied to a file a caller handed in -- because `dict.get(...)` is not a name a
//		general model can claim.
//
// TAINT THROUGH A DEPENDENCY THAT IS NOT IN THE TREE: DECIDED, AND IT KEEPS FLOWING.
// An unresolved call into a package with no source here propagates taint from its
// arguments to its result, and it will continue to. The precedent that looked like it
// pointed the other way does not: a store read stopped taking taint from its argument
// because a lookup ANSWERS WITH WHAT WAS STORED, which is a fact about that operation.
// An arbitrary unread callee offers no fact at all, and narrowing on the absence of one
// would make the engine quietest exactly where it knows least. The risks are not
// symmetric either -- assuming taint survives costs precision, assuming it dies costs
// recall, and recall is what this engine is short of.
//
//	What changed is that the assumption is now NAMED. `Model.Attests` asks whether
//	anything in this model has a statement about a call -- a channel, a transform, a
//	store, a classification, a shape -- and a hop into code that is not in the tree and
//	that the model has never heard of is recorded as `Hop.Assumed` and listed in
//	`Finding.Assumptions`, which the report prints as "assumed, not established". The
//	discriminator is deliberately not a name and not a lockfile: it asks what this model
//	covers, so it stays right as the model grows and needs no registry and no guess about
//	which directory a dependency was vendored into. Measured, it is selective rather than
//	blanket: 20 of the 91 findings across the ten repositories carry an assumption and 71
//	do not, and on uptime-kuma it is 5 of 14 -- four `badge-maker.makeBadge`, one
//	`feed.Feed`. It names language builtins this model has never described
//	(`Promise.reject`, `URL`, `decodeURIComponent`) alongside unread packages, and that is
//	the accurate reading rather than a lapse: what was checked is that nothing here
//	implements the call and nothing in this model describes it, which is equally true of
//	both, and the printed sentence says exactly that and no more.
//	It changes no verdict and no gate, and that is the decision rather than an omission:
//	all seven of the original badge findings were adjudicated DISPUTED, which means
//	unanswerable, and they were unanswerable because the report never said which hop the
//	question was about. Naming it is what a reader needed; suppressing it would have
//	answered a question nobody could answer.
//	NOT CAUGHT: the consolidation the same entry asked for -- one finding about
//	`makeBadge` with several reaching routes. Those are four distinct sinks in four
//	distinct handlers, and merging findings across functions is the per-branch
//	duplication entry's work, not this one's.
//
// A claim without a reason is not accepted. See TestEveryClaimStatesItsReason.
var claims = map[string]Claim{
	"CWE-78": {State: Asserted, Reason: "untrusted data reaching a described command API, across functions and modules -- including a value that never came from a request at all. A Django management command's `handle` is an entry point whose parameters argparse fills in from what a person typed, so `os.system(\"ping \" + host)` in a command is the same defect it is in a route and is claimed as one. It is reported at warning and does not gate, because the trust says an operator supplied it: whoever can run `manage.py` already has the host, and failing a build on that would claim a stranger could. `**options` is a parameter as much as a named one, so an option read out of it is covered too. What is NOT covered is the argument parser itself: the declared names are recorded on the entry point as evidence and no value is taken from `add_arguments`, because argparse hands the value to the handler and that is where it is classified",
		By: []string{"untrusted-to-interpreter", "upstream-response-to-interpreter"}},
	"CWE-73": {State: Asserted, Reason: "untrusted data choosing the executable a process launches",
		By: []string{"untrusted-to-interpreter", "upstream-response-to-interpreter"}},
	"CWE-95": {State: Asserted, Reason: "untrusted data reaching a language evaluator: eval, Function, Python exec",
		By: []string{"untrusted-to-interpreter", "upstream-response-to-interpreter"}},
	"CWE-89": {State: Partial, Reason: "untrusted data COMPOSED into the statement argument of a described SQL API, where composed means composed into the value THIS sink receives rather than anywhere in its history. A parameterized call cannot match, because the channel names only the interpreted argument. Known imprecision: `execute` is also what a CQRS bus and a SQLAlchemy Session are called on, and neither takes a statement string -- telling them apart needs the receiver's type, which one frontend supplies patchily and the other not at all, so those report at reduced confidence rather than being excluded A recall audit named one shape this cannot reach: pg-promise calls its query methods `one`, `many`, `any` and `none`, which are 2020 call sites across the clean corpus and almost none of them a query -- and the receiver that would tell them apart is the result of calling the result of a require, a callee the frontend does not resolve. A pg-promise application is analysed for everything else and silent about its SQL. A value a LOOKUP returned is no longer taken to be the key the lookup was given. A read from a store answers with what was WRITTEN there, so an ORM query, a cache `get` and `localStorage.getItem` propagate nothing from their criteria into their result -- which removed six false positives across two repositories with no true finding lost, among them a 49-hop path from an ActivityPub queue processor onto raw SQL. Reads are recognised either by a method name that belongs to one library's data-access API, by a receiver the frontend typed as a container, or by a receiver that says in its own spelling what it is; `fastify.get`, `axios.get` and `Array.prototype.find` match none of those and are untouched. The READ half is now claimed in the place where a store is actually read back: a scheduled job and an event-bus consumer are entry points, so a cron job reading a column an earlier request wrote and interpolating it into SQL is anchored and gates -- the trust travels with the write, and that write was a remote caller's",
		By: []string{"untrusted-to-interpreter", "upstream-response-to-interpreter", "stored-to-interpreter"}},
	// Subsumes the variants that name a PAYLOAD spelling -- script tags, script in an
	// attribute, alternate identifier characters. The rule proves untrusted data reaches
	// a response body parsed as markup and never inspects what the data says, so those
	// are the same finding at the same line. CWE-81 is excluded below, because what makes
	// it different is where the data came FROM, which this engine does look at.
	"CWE-79": {
		State: Partial,
		Reason: "untrusted data reaching a response body parsed as markup, with " +
			"context-wrong encoders recorded as insufficient -- AND escaping decided " +
			"inside a view, which is where a server-rendered application decides it. " +
			"Both frontends read their ecosystem's templates and record, per " +
			"interpolation, whether the engine escapes it: EJS, Handlebars, Mustache, " +
			"Pug, Nunjucks and Swig on one side, Jinja2 on the other. The finding points " +
			"at the template line rather than at the handler, and it names the `| safe` " +
			"that removed the encoder as a hop of its own: autoescaping is on in both " +
			"template languages, so an unescaped interpolation is a decision somebody " +
			"wrote down and an absent encoder is a different fact from a removed one. " +
			"The context no longer has to be written at the render call. A mapping " +
			"handed over whole -- `render_template(name, **ns)` -- supplies the view's " +
			"names through its KEYS, and the core resolves those program-wide: a " +
			"mapping literal's entries, an assignment into a subscript, `dict(k=v)`, an " +
			"`update` from another mapping, and the mapping a called function returns. " +
			"That is what a base handler's namespace hook and an application-wide render " +
			"helper are, and neither writes both halves in one place. Its cost was " +
			"measured before it was claimed: across ten production repositories it " +
			"roughly doubled the interpolations that carry a value -- searxng 112 to " +
			"215, jupyterhub 54 to 69 -- and changed NOT ONE finding in either " +
			"direction. Every key rests on a literal somebody wrote; a computed key " +
			"names nothing a view can read and binds nothing. What stays out of reach " +
			"is stated rather than assumed: a view name not written in the render call, " +
			"a name two templates could answer to, an interpolation that is not a plain " +
			"access path, and a POSITIONAL context object -- Django's " +
			"`render(request, name, ctx)` and Express's locals built anywhere but the " +
			"call. The Django half was built, measured and withdrawn: it made 188 views " +
			"and 101 renders visible in healthchecks where there had been none, wrote " +
			"621 interpolation sinks, and produced exactly one finding -- a URL-target " +
			"report whose taint arrived through a helper's return merged across its " +
			"call sites, so the entry point it names cannot reach the page it names. " +
			"Zero true findings against one false one is worse than silence, and the " +
			"limit it depends on -- no call-site context (docs/IR.md) -- is not this " +
			"rule's to fix. One further miss is a " +
			"measurement rather than a structural limit: an engine configured with " +
			"autoescaping off globally makes every interpolation in its templates " +
			"unescaped, and the configuration is not connected to the files it governs. " +
			"A third place escaping is decided needs no call and no template: assigning " +
			"to `innerHTML` parses what it is given as markup, which is the browser-side " +
			"twin of an unescaped interpolation and is why a rule that watches calls " +
			"could not see it. `textContent` is the same assignment with the parsing off, " +
			"and is the fix. URL-valued href, src and action destinations are a distinct " +
			"browser interpretation after markup parsing: when caller data supplies the " +
			"whole value, HTML escaping does not constrain javascript or data schemes. " +
			"A `<script>` element is a fifth place, and it is neither markup nor a " +
			"JavaScript string: the HTML parser ends the element at the first " +
			"`</script` whatever the JavaScript says, and does not decode entities in " +
			"there. So HTML-escaping answers it -- the `<` is gone -- and escaping for " +
			"a JavaScript string does not, because `json.dumps` and `JSON.stringify` " +
			"escape the quote and leave the `<`. Both are declared, and an encoder that " +
			"answered the wrong question is recorded as considered-and-insufficient " +
			"rather than as nothing tried (ADR-006). Asserted by fixture and not yet " +
			"observed on production code: jupyterhub writes exactly this shape at " +
			"share/jupyterhub/templates/page.html:86, and the value reaching it is a " +
			"username read back out of the database, which no source in this build " +
			"classifies. " +
			"Reporting the configuration instead was counted and declined -- 15 mentions " +
			"of autoescape across the clean corpus, the two that disable it being a " +
			"LaTeX renderer and a code generator, where HTML escaping would be the bug. " +
			"A fourth place the data can come FROM is claimed and its cost is stated in " +
			"full, because it is the noisiest claim in this file: a value one request " +
			"WROTE to a database and another reads back is still the first caller's, and " +
			"stored cross-site scripting is that sentence at a markup channel. The " +
			"connection names the TABLE and the COLUMN on both sides -- the table from " +
			"the callee spelling that every ORM writes into its own calls, the column " +
			"from the option keys the write was written with -- and it requires the write " +
			"to be reachable from an enumerated entry point and the read to be somewhere " +
			"the write is not. Naming only the table was built first and withdrawn on " +
			"measurement: it reached 2179 values in a 57k-line repository, more than the " +
			"1914 the first-order class it derives from reached, and produced one finding " +
			"in ten repositories -- a file path built out of an auto-increment " +
			"`collection.id`, because a write of a display name had connected to a read " +
			"of the primary key beside it. With the column named on both sides the rule " +
			"produces NOTHING across those same ten repositories and 1.5 million lines, " +
			"and that is the honest state of it: asserted by a fixture, never yet " +
			"observed on production code, so its precision is undefined rather than " +
			"perfect. Four misses are named rather than left to be discovered. A write " +
			"whose columns are assembled elsewhere -- Prisma's `create({ data })` with " +
			"the object built in another function -- names no column and connects to " +
			"nothing. A SQLAlchemy attribute assignment is not a call and is not a write " +
			"here, which is why jupyterhub's stored XSS through `setattr(user, key, " +
			"value)` is not reached. A stored value that becomes an object KEY rather " +
			"than a value was built and withdrawn separately: umami's SQL injection needs " +
			"it, the propagation cost one new false positive across the batch and " +
			"produced no true one, and it is not in this build. And a session and browser " +
			"storage are modelled as stores but are not claimed as second-order SOURCES, " +
			"because a session is one caller's own data returning to that same caller. " +
			"The read half reaches background code now: a scheduled job and an event-bus " +
			"consumer are entry points, which is where a store is read back long after " +
			"the request that filled it, and it is the write's trust the finding carries " +
			"rather than the timer's",
		By:       []string{"untrusted-to-interpreter", "markup-assignment", "stored-to-interpreter", "untrusted-url-target", "upstream-response-to-interpreter"},
		Subsumes: true,
	},
	"CWE-116": {State: Partial, Reason: "caller data composed after a fixed URL prefix in an href, src or action attribute/property, without an encoder for URL-component syntax. This is deliberately not SSRF: the program-written prefix fixes the host, while an unencoded slash, question mark, fragment or dot segment can still change the resource. Quoted URL-valued template attributes and direct DOM property assignments only; helper expressions and unquoted attributes are left unclaimed rather than guessed",
		By: []string{"untrusted-to-interpreter", "untrusted-url-part"}},
	"CWE-81": {State: Asserted, Reason: "failure detail reaching a markup channel. Not subsumed by CWE-79 even though it sits beneath it: what distinguishes it is the SOURCE, and this engine classifies error detail separately from caller input precisely so it can tell them apart -- an error message is where a program repeats back what it was given, which is how the message becomes script",
		By: []string{"error-detail-into-markup"}},
	"CWE-209": {State: Partial, Reason: "caught error detail reaching a channel visible outside the system; cannot judge whether a message is generic enough",
		By: []string{"internal-detail-outward", "development-error-handler"}},
	// Subsumes CWE-566, which is the same weakness with the record's identifier being a
	// SQL primary key. Whether the selector is a primary key, a document id or a slug is
	// a detail the ownership question never asks about.
	"CWE-639": {State: Partial, Reason: "four rules, and the second exists because the first had to presume something. `unowned-record-access` reports a record selector chosen by the caller with no relation to the caller's identity, and it accepts a call carrying that identity as the relation -- which is right for an assertion helper and wrong for a permission check that names a scope. `authorization-scoped-elsewhere` states the relation instead: when an enforced check is scoped to one key and a store write the check admitted is keyed by a different one, the analysis looks for something tying them -- a lookup carrying both, a comparison between them, a comparison against the actor, or a selection that carries both -- and reports when there is none. Existence does not count: `featureExists(id)` proves the row is there and mentions the authorized key not at all. Measured over ten production repositories it produced two findings and both were true, at unleash's segment controller and umami's report endpoint. What it does not catch is stated: an authorization that lives in route middleware rather than in the handler, because the relation is judged inside one function and a middleware gate is not in it; a write in a service the handler calls, for the same reason; a key spelled as a NAME rather than an id, which loses unleash's `featureName` because `name` is what most payload fields are called; a key spelled as a SLUG, tried and withdrawn after umami's link and pixel rename endpoints -- whose purpose is to set the row's own slug -- were two of four findings; and a CREATE, whose identifiers are the new row's own fields rather than a selector reaching an existing one. Judgements on entry points the framework handed no identity are set aside rather than reported: 42 of those were adjudicated by hand against sixteen production repositories at 0.00 precision, and setting them aside cost nothing on the vulnerable corpus. One further limit is a measurement rather than an argument: a program having an identity source SOMEWHERE is not evidence that a given handler can reach it. Recognising a verified JWT as an identity turned n8n from honestly not-evaluated into 181 findings, and the ones examined were invitation and password-reset routes that are unauthenticated by design and have no owner to check against -- six true positives in the vulnerable corpus did not pay for that, so the analysis stays quiet where the identity it needs is not visible from the handler. `authorization-through-a-different-accessor` is the third, and it exists because the second one still needs the caller's scope to have arrived in the REQUEST. Very often it did not: the authentication layer established it, the handler holds it inside a context object, and the question the handler asks is `may I act here` rather than `may I act on THIS`. What that leaves comparable is the ACCESSOR -- medplum's rotate-secret handler asks `ctx.repo.isProjectAdmin()` and then reads and rotates the client application through `ctx.systemRepo`, a sibling accessor of the same context constructed with `superAdmin: true`, keyed by the route's own id and with nothing relating that record to the caller's project. The rule states the swap and nothing about privilege: it does not know which of the two accessors is the elevated one, and a handler that asks and acts through the same accessor is silent whichever one it chose. Measured over the same ten production repositories it produced ONE finding, medplum's, which an independent review and a source adjudication had already confirmed, and no others -- and the same measurement is what let its operation list include reads as well as writes, which the rule above cannot afford: widening it added no finding the write words had not already produced. What it does not catch is stated. A check whose receiver is not a property of anything -- a bare `requireAdmin()` -- names no accessor and there is nothing to compare. A check written as a decorator or a middleware is not in the handler's body. An accessor reached through a named helper rather than through a callback the handler wrote inline is not followed, for the reason the key relation gives: deciding which caller's gate governs which callee's operation is a judgement this analysis declines. And the check has to be RECOGNISABLE as an authorization from its name, because with no identity value handed to it there is nothing else to go on -- a permission predicate named in a vocabulary this list does not hold reads as an ordinary guard and the handler is passed over" +
		"`authorization-declared-elsewhere` is the third, and it exists because the second needs two CALLS and a whole framework idiom has neither. A Django REST Framework view is a class of four assignments -- `permission_classes`, `queryset`, `lookup_url_kwarg`, `serializer_class` -- and the framework does the checking and the fetching; there is no handler body to build a control-flow graph over, so the rule above sees an empty class and says nothing. The relation is stated over the declarations instead: the request key the permission classes consult against the request key the framework resolves the record from, with the application's own `get_queryset` narrowing and DRF's `has_object_permission` hook read as the two places a correct view states the relation. The methods the view does write are judged under the same declared gate, which is what reaches a bulk delete keyed off the request payload -- the framework never calls `get_queryset` for a method the application wrote itself, so a project-scoped list query beside it constrains nothing. Measured over the seven Python repositories of the clean corpus before it was written (ADR-015): wger declares 52 of these views and paperless-ngx registers 71 classes, and neither produces a single match, because their permissions consult no URL keyword at all -- they narrow by the requester in `get_queryset`, which this rule is silent about by construction. Every match is in doccano: eleven distinct declarations, all adjudicated true against source, while the other nine production repositories are byte-identical before and after. Reads are reported for the DECLARED selection where the rule above reports only writes, and the difference is structural rather than a change of policy -- `get_object()` resolves ONE row and serves it to GET, PUT, PATCH and DELETE from a single declaration, so there is no read to separate from the write, while a write in a handler body still has a verb to read and the restriction applies there unchanged. Widening the older rule's verb list to nineteen read verbs was measured separately and changed not one finding on any of the ten repositories, so it was not done. What this rule does not catch is stated: a view whose lookup key is DRF's unwritten `pk` default, because the declaration is the evidence and its absence is not evidence of `pk`; a permission class that reads its key from anything but `view.kwargs`; a re-parenting write under a declared gate, because a Django write puts its whole selection on the receiver and leaves no argument position to compare depth against; a query narrowed through a helper the view does not own; and every framework but DRF, because a declaration means what its own framework says it means and no other one has been measured",
		Subsumes: true,
		By: []string{"unowned-record-access", "authorization-scoped-elsewhere",
			"authorization-through-a-different-accessor", "authorization-declared-elsewhere"}},
	"CWE-260": {State: Subsumed, Reason: "a password in a configuration file. The half written in SOURCE is caught by the rule for CWE-798 and reported under that number -- `app.config[\"SECRET_KEY\"] = \"...\"` and `app.secret_key = \"...\"` are a configuration assignment the frontend lowers like any other. The half in a .env, a YAML manifest or a deployment template is genuinely out of reach: those files are not source and are not read",
		By: []string{"hardcoded-secret"}},
	"CWE-321": {State: Partial, Reason: "two shapes. A cryptographic key written as a literal into a call that must hold one -- the same rule as CWE-798, asserted in its own right because the argument positions it describes ARE key arguments; only those three APIs, and a key handed to anything else is a stated miss. And a PEM private key block anywhere in the source at all, which needs no call and no destination because the value's own shape is the whole of the defect. Measured at one across twenty-eight production repositories, and that one is a real EC key in an Apple Sign-In example",
		By: []string{"hardcoded-secret", "private-key-block"}},
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
			"path.basename and Flask's send_from_directory are recognized as confining it. " +
			"An archive is covered from both ends by the same rule: the library call that " +
			"unpacks a whole one at once is reported where it is written, and a program " +
			"that walks the entries and writes each one itself is reported on the entry " +
			"NAME -- because the loop variable carries what the collection carried, and " +
			"the collection came out of opening an archive the caller sent",
		By:       []string{"untrusted-to-filesystem-path"},
		Subsumes: true,
	},
	"CWE-918": {State: Partial, Reason: "untrusted data forming the destination of a described outbound request. Whole, or composed with the caller's value FIRST -- because if nothing precedes it the program named no destination at all, which is how one of the two forgeries in the vulnerable corpus is written. A URL whose host is fixed by anything at all before the caller's part leaves them only a path and is not reported. Asking instead whether a literal at the call names a scheme was tried and measured: it readmitted the true one and two production call sites with it, because a program keeping its base URL in a constant writes no scheme at the call either. The client list is the real limit and it is a list -- right about everything it mentions and silent about everything it does not, which is why a client nobody had added carried a forgery a recall audit found by reading. One shape that WAS reported and should not have been is gone with the store model: a username selecting a user row does not make that row's stored `movedToUri` the caller's choice of destination. " +
		"Two shapes the list was silent on are now described, and both were misses of the CALL rather than of the flow. The verb-as-argument spelling -- `requests.request(method, url)`, which is how a PROXY is always written, because a handler forwarding whatever method arrived cannot call `get` -- had no channel for requests at all and pointed at argument zero for httpx, which is the method and never the address. And `urljoin` is now described as a REFERENCE RESOLVER rather than left to the whole-value rule: RFC 3986 says a reference beginning `//` is a network-path reference whose authority replaces the base's, so the literal `/` an application writes in front of caller data anchors nothing, while the same concatenation handed straight to a client still does. archivebox's `/opencode/<path>` proxy needed both facts and one route source. " +
		"WITHDRAWN, and recorded because the measurement is the argument. Second-order forgery -- an upstream response choosing the next destination -- was tried by adding `url` to the denied set of `upstream-response-to-interpreter`, and it is not built. It found linkding's preview-image loader, which follows an `og:image` out of a page it fetched for the caller and is a real second hop; it found the same shape twice in wger, following an image URL out of a remote instance's JSON. It also found three where the upstream is a host the application configured -- documenso fetching an S3 object by a presigned URL its own API returned, documenso's CSC signing client, medplum's CLI following a tarball URL out of npm registry metadata -- and every one of those is an integration doing what an integration does, which is the exact reading that class already declines to make about a response sent onward. Three of six, with all five beyond the first landing below the gate, is not a rule. What separates the two halves is visible and not yet expressible: in linkding the upstream is itself a host the CALLER chose, and in the other three it is one the deployment chose. Saying that needs a source rule conditioned on another classification reaching the source call's own argument, which no seeding strategy here can state",
		By: []string{"untrusted-to-outbound-destination"}},
	"CWE-502": {State: Partial, Reason: "untrusted data reaching a deserializer that reconstructs objects rather than parsing data; yaml.safe_load and JSON.parse are deliberately not described because they build data and never behaviour",
		By: []string{"untrusted-to-deserializer"}},
	// Asserted against the catalog's own detection-method field, which records none for
	// this entry. That costs a working rule and a fixture, which is the only way the
	// denominator is allowed to move (ADR-007).
	"CWE-698": {State: Asserted, Reason: "a rejection the program wrote and then walked past. The engine's only judgement about the SHAPE OF THE GRAPH: an error status is written into the response and the work it was refusing is still unavoidable, so the refusal is a status code and nothing more. It needs no declared expectation, which is why it is worth having -- the program has already said in its own code that the request should not proceed. Three shapes that look identical are excluded because they are correct: a branch whose other side does the work reconverges on nothing, a helper the language declares `never` does not come back, and a catch handler runs INSTEAD of the rest rather than after it. A redirect is deliberately not a rejection: `res.redirect(next)` after a successful login is the same call as after a failed one, and one production repository writes eight of the first kind in a single function. " +
		"`rejection-built-and-discarded` is the second shape and the smaller claim: a response CONSTRUCTOR -- `flask.redirect`, `make_response`, `jsonify`, Django's `HttpResponse*` family -- whose result is used by nothing at all, in a function where another call to the same constructor is returned. Those calls send nothing; the returned value is the whole of what they do, so a caller who drops it has written a line that does not exist. The sibling is what makes it sayable rather than a report of dead code: the program has already written down, one branch away, what this branch was supposed to end with. Measured over ten production repositories it produced two findings, both in searxng's Sec-Fetch filter, where the `Sec-Fetch-Mode` branch returns its redirect and the `Site` and `Dest` branches build the identical one and fall through to `return None`. " +
		"Python's status spellings were built and withdrawn after reading every measured site. A `RejectWrite` over `Write.Path` and the existing post-dominance question produced zero new findings from the 40 assignments it was proposed for. All five in searxng and all 33 in healthchecks set the status of mocked outbound responses in tests; they are inputs to the code under test, not refusals written by a handler. JupyterHub's two spellings initialise HTTP-error metadata rather than a response, and its one `self.set_status(403)` call renders the failed-login page and finishes the response in the same block. Adding the call name alone therefore produced nothing; treating same-block response rendering as the work being refused would turn that correct handler into the only finding. `StoreRule` can name the path of a write but cannot express the control-flow relation, and adding that relation bought zero true sites, so these Python spellings remain an explicit miss rather than a zero-yield rule. " +
		"Four things it does not catch, each because the evidence it turns on is absent. A constructor discarded in a function that returns none of its own kind is dead code and is not reported, which is the same rule read from the other side. A construction assigned to a variable that is then never used is a use as far as this is concerned, because the assignment consumed it. A rejection dropped in one function whose sibling lives in another is not compared, since the pairing is within a single function. And the list is response constructors only: `res.status(403).json(...)` has already answered by the time it returns, so discarding what it hands back is a matter of style, and putting a sender on that list would report the ordinary spelling of every Express handler ever written",
		By: []string{"rejection-without-return", "rejection-built-and-discarded"}},
	"CWE-59": {State: Partial, Reason: "a tar archive extracted without the parameter that decides what a member may BE. A member can be a symbolic link, and extracting one writes through it to wherever it points -- the `..` member everybody knows about is the other half and is claimed under CWE-22, and the same one parameter settles both. Python added `filter=` for exactly this and is making `filter=\"data\"` the default, which is as clear a statement as a language ever makes that the old call was wrong. Zipfile is deliberately not matched: it has no such parameter, and its members are judged by where the archive came from. An ABSENCE rule, so it speaks only where the keywords were enumerated -- a call whose options came from somewhere else is unknowable and is passed over. Nothing is claimed about a link followed anywhere OTHER than an archive: that needs the filesystem, not the source",
		By: []string{"unfiltered-extraction"}},
	"CWE-601": {State: Partial, Reason: "untrusted data forming the WHOLE destination of a redirect, including where the response object was handed to a HELPER -- a handler that got long passes `res` along, and a channel that asks whether the receiver is the entry point's second parameter used to stop at the call boundary and answer no, so nothing written in the helper was a response at all. It is answered from the call sites now, and only when they agree. A path within the application cannot leave it and is not reported. Applications very often validate a redirect target with a helper of their own or behind an `is_safe_url` check, and whether such a check is CORRECT is not something this engine can decide -- it does not model guards at all, so those report rather than being cleared, and in a frontend without types they land below the gating tier rather than above it. Three of the false positives this once produced were one step: a route parameter SELECTED a stored row and the row's own URI was redirected to, and the engine read the selection as though the parameter had composed the destination. A read answers with what was stored, and it no longer does",
		By: []string{"untrusted-to-redirect"}},
	"CWE-328": {State: Partial, Reason: "a digest from an algorithm broken against collision, judged by what the program DOES with it rather than by the algorithm's name. The call is a classification -- `hashlib.md5`, `hashlib.sha1`, and `createHash`/`hashlib.new` given a broken algorithm as a literal -- and the finding is at the use: an equality comparison, a verification call, a password field, or membership in a container whose name says it is a blacklist/blocklist/denylist. The membership-test-not-a-comparison rule names that container because `digest in cache` is character-for-character the ordinary cache spelling and is deliberately silent. The name-matching rule this replaced produced 42 findings across ten production repositories and an independent reader judged 39 of them worthless: rate-limit bucket keys, a Wikimedia directory path, an ETag, an exported helper nothing calls, and twenty-six request signatures a remote site's protocol demands. What they have in common is that the program establishes nothing by the digest, and what the real ones have in common is that it does. Two misses are stated rather than hidden: a digest handed across a promise boundary is not followed, and an algorithm chosen at runtime is not matched and not guessed at. A denial set named with application-specific vocabulary is also missed rather than inferred. HMAC is deliberately outside this: its soundness rests on the key and the construction rather than on collision resistance. " +
		"The comparison half was then measured a second time and narrowed again, because the operator alone does not say what a comparison decides: across the same ten repositories it produced four findings and an independent reader judged none of them worth reporting. Three are now silent for two reasons that are both facts about the value rather than about the algorithm. The compared value must BE the digest and not something it was built INTO -- linkding names a preview file `f\"{md5(url)}{extension}\"` and compares the NAME with the one on the row to decide whether the preview changed, which is the distinction the unsalted-hash channel has drawn since it was written. And where the other side is WRITTEN INTO THE SOURCE it must be written as a digest, a run of hex long enough to be one -- medplum addresses Redis's script cache by a Lua script's SHA-1 and tests the numeric reply for `1`, so the class rode through an unresolved call into a value that is not a digest and never was. A digest recorded in base64 is not recognised as one and is a stated miss. The fourth, mitmproxy's htpasswd verifier, is a real weakness this rule was naming wrongly and is now reported under CWE-916 instead: a collision does not produce a second password for a digest somebody else chose, and the comparison is refused here by the same password-field names the store rule uses. " +
		"Two doubts are recorded rather than acted on, both because acting on them would silence a shape the corpus asserts. The DENIAL-LIST half is the first: searxng's onion filter was read as this rule's one true finding in that repository and an independent reader has since called it false, on the ground that a colliding hostname would also be DENIED -- membership over-blocks and does not bypass, and getting past a denial list needs no collision at all because any other hostname will do. What that argues is that membership is worth reporting only where presence GRANTS something, which is not a distinction a container name can make. The second is pdf.js's test-manifest check, which an independent reader called false because it warns and fails test setup rather than authorising anybody: the comparison is a genuine integrity assertion and the engine already declines to gate on it, since nothing on the enumerated surface reaches it",
		By: []string{"weak-digest-compared", "weak-digest-verified", "weak-digest-as-credential", "membership-test-not-a-comparison"}},
	"CWE-295": {State: Partial, Reason: "certificate verification disabled by a literal argument or option: `verify=False` on a Python request, and `rejectUnauthorized: false` anywhere at all, because that option name means one thing in Node and a list of the clients it can be handed to would be wrong the moment somebody used a different one",
		By: []string{"disabled-certificate-check"},
		// Turning verification off turns off everything verification does: following the
		// chain to a root, and asking whether the certificate was revoked. The analysis
		// sees the option and never asks which sub-check the caller had in mind, so the
		// variants beneath this are the same line under narrower names.
		Subsumes: true},
	"CWE-489": {State: Partial, Reason: "a debug server started with debug enabled by a literal keyword, at either Python framework: Flask's `run(debug=True)` exposes a console that executes what is sent to it, and aiohttp's `Application(debug=True)` answers a failed request with the traceback and the local variables of every frame. Narrow on purpose: this is the one shape where the decision is written at the call, and debug flags read from configuration or the environment are not literals and are not matched",
		By: []string{"debug-mode-enabled"}},
	"CWE-942": {State: Partial, Reason: "credentials allowed on cross-origin requests while the origin is wildcarded or reflected. A conjunction rather than a single bad value, because either half alone is ordinary: a public API wildcards its origin, and a first-party front end sends credentials to a named one",
		By: []string{"permissive-cors"}},
	"CWE-327": {State: Partial, Reason: "a broken cipher or a mode that leaks plaintext structure, named as a literal in the call; unlike a weak hash this gates, because nothing needs encryption for a purpose that does not need encryption",
		By: []string{"weak-cipher"}},
	"CWE-1333": {State: Partial, Reason: "three directions of one weakness, and they need different evidence. A caller who writes the PATTERN is reported wherever untrusted data reaches a regular-expression constructor -- rare, and unambiguous. A caller who feeds a long string to a pattern that BACKTRACKS is how a process actually gets stopped, and that needs two facts at once: the pattern is one that can churn, and something a caller chose reaches it. Neither is a finding alone. The third is the same weakness written where no flow can see it: a route that validates its request with a SCHEMA never writes the match -- it writes the pattern, hands the schema to the framework, and the string and the pattern meet inside the validation library -- so the evidence is the pattern plus the route it is written in, which is umami's pre-authentication ReDoS exactly. The pattern test is structural and reads two shapes: a quantified group with no marker to separate its repetitions (`(a+)+`, `(a|a)*`), and a repetition standing next to a repeated group whose leading marker that repetition can also match -- `[a-z0-9-_]+(-[a-z0-9-_]+)*` blows up and `[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*` does not, and only comparing the two character sets tells them apart. Everything else is a stated miss, and there are five. A pattern computed at runtime is not written down and is not guessed at. The MULTIPLICATIVE shape -- one scan per token of an uncapped split, each scan linear -- is resource exhaustion rather than backtracking and belongs with those rules. Polynomial backtracking is not claimed; only the exponential shapes are. The mirror of the adjacent shape, a repeated group FOLLOWED by a repetition it overlaps, is not matched. And the schema rule speaks only for zod, Joi and yup, only in TypeScript, only when the pattern is a literal or a module-scope constant it can resolve through the import -- a Python schema library has no rule, and a route registered in a test module is deliberately silent because a fixture is not an attack surface",
		By: []string{"untrusted-to-regex", "untrusted-to-catastrophic-regex", "catastrophic-pattern-in-schema"}},
	"CWE-330": {State: NotBuilt, Reason: "needs a notion of which randomness is used for a security decision, which a call shape alone does not carry"},
	// A key written into a call that must hold one. The CATEGORY of secret is something
	// this rule does encode -- it names key arguments -- so the crypto-key variant is
	// asserted directly rather than subsumed. The password variant has its own rule now,
	// matched by option NAME rather than by argument position, which is how a connection
	// string asks for one.
	// Anti-CSRF, and the clearest case in the model for deciding from the population
	// rather than from a rule (ADR-010).
	"CWE-352": {State: Partial, Reason: "a state-changing entry point missing the anti-CSRF control most of its comparable peers apply. There is deliberately no rule for a route that simply has no token check: whether one is needed at all is a fact about how the program authenticates, and on an API reached with a bearer header a token buys nothing. The population is the only evidence of that fact -- a program carrying the check on its other routes has declared that its routes are reached with a cookie. Safe methods are exempt whatever their peers do, because a GET is not supposed to change state and every CSRF middleware lets one through without a token. Inferred and therefore informing rather than gating; measured at zero across both corpora, since CSRF middleware in the wild is applied application-wide and a control on every entry point distinguishes none of them",
		By: []string{"expectations"}},
	// Session fixation. The subject is the identity change -- either a login operation or
	// a direct write to the principal slot -- and the policy asks whether rotation
	// accompanies it.
	"CWE-384": {State: Asserted, Reason: "a direct change to the session's principal with no identifier rotation in the same request. The classification is the identity change, not a session write: application namespaces such as wger's `trainer.identity` and `gym.user` are excluded even though their leaf names resemble principals, which removes the rule's only two findings across twenty repositories. Framework login operations that rotate intrinsically -- Django login and Passport logIn -- count as the rotation themselves, alongside explicit regenerate, cycle/reset and client-side clearing. Because the remaining finding is an argument from silence it is deliberately generous about where that rotation may live -- the calls the function makes, the callbacks it hands out, the helpers it calls and its own callers -- and it stops ascending at an entry point, since a sibling route registered on the same module has nothing to do with this one. The low-level direct assignment remains covered because it is itself an identity change; clearing the principal and writing an element of somebody else's session collection are not",
		By: []string{"session-not-rotated"}},
	"CWE-798": {State: Partial, Reason: "a value THIS program's own security rests on staying secret, decided by what the program does with it rather than by what the value says -- the same question the weak-digest rule asks, one level down. Four uses answer it and each has its own rule: a key argument passed as a literal to a signing or session call; a literal assigned to a configuration key whose name holds the word secret, password or key; a literal that a credential the CALLER sent is compared against, which is the program admitting somebody by a value that is in every clone of the repository; and a value whose own SHAPE is a credential -- a password in a connection string, a signed token, and the six provider-issued identifiers whose format their issuer defined. A key read from the environment or a vault is not a literal and never matches. The configuration assignment includes a literal on the default side of `X || literal`: when X is absent that literal IS the option, and recording only that fallback rather than every object-literal property avoided the 1463 findings the unrestricted shape produced in one measured corpus. Across ten production repositories the fallback added two candidates; Unleash's default `secret` was real, while Linkwarden's test-account password was a placeholder and is excluded by the same test-module bar as a direct literal. The configuration shape is matched on a WORD in the key because configuration keys are compound, and it excludes three literal shapes measured on the clean corpus that a key-named setting holds when it is NOT holding a key: an endpoint the credential is sent to, a sentence from a settings schema, and the mask a value is replaced with before it is logged. The word token is deliberately not in that list -- across twenty-eight repositories every configuration key holding it held a URL, a header name or a form field. The SHAPE rules used to stand on the shape alone and no longer do. Measured across ten production repositories, 27 of the 56 false findings left in the batch were public client identifiers and all 27 were in one program: Firebase web API keys, a Google Drive playback key, and Adobe Primetime software_statement attestations in yt-dlp, every one of them a value the third-party site publishes in its own web client. yt-dlp is a CLIENT of every site it has an extractor for and there is no server in it whose door any of those keys opens. So a shape finding is now withheld where the program's only use of the value is to hand it to somebody else's service: filed under a request part -- a query parameter, a header, a body field -- or handed to a call that names an absolute URL written in the source, or built into one. This is deliberately not a list of vendor prefixes, because the shape is not what makes a value public and the next provider's shape will not be recognisable; what separates a client's NAME from a client's SECRET is the request part it is filed under, and the model reads that. A value under client_secret, Authorization or token is the program proving who it is, and it is reported. Five misses are stated rather than hidden. A value with no visible use is still reported, which is the deliberate direction: a key in a repository is in every clone of it whatever reads it, so the withholding needs positive evidence and silence is never evidence. A value destructured out of a TUPLE loses the name it binds, because neither frontend lowers an unpacking target, and four Adobe attestations in yt-dlp are reported for that reason and no other. The role walk stops four values and two function boundaries out from the literal, so a constant consumed five frames away is undecided and therefore reported. A credential-shaped literal in a TEST module that the test only asserts against is reported, and five expected JWTs in yt-dlp's own utility tests are exactly that -- suppressing them would mean suppressing a real key committed to a test, which is how credentials actually leak. And a provider-issued ACCOUNT credential presented to its own provider is separated from a client identifier only by the option name it travels under: handed to a library that names no URL and no option, the engine keeps reporting it, and handed to a request under a part named neither for a secret nor for anything else, it would not",
		By: []string{"hardcoded-secret", "credential-in-url", "signed-token", "aws-key-id", "github-token", "slack-token", "stripe-key", "google-api-key", "npm-token", "credential-admits-caller"}},
	// Members of the catalog's own Top 25 that apply to these languages. Named rather than
	// left blank, because this list is the closest thing the project has to a prioritised
	// backlog that nobody wrote by hand.
	"CWE-306": {State: Partial, Reason: "an entry point missing an authentication control most of its comparable peers on the same mount apply. Inferred from the population and therefore informing rather than gating (ADR-010). The mount is part of the population because registering a route on a deliberately public router is an author decision: medplum's public FHIR router produced the only two findings across twenty repositories when it was compared with a separate protected router in the same file, and both were false. It still cannot distinguish an endpoint unauthenticated by design from one that forgot inside one shared mount, which is what a declaration supplies",
		By: []string{"expectations"}},
	"CWE-862": {State: Partial, Reason: "three rules, and all three say the same thing about a control that is absent: the program performs it somewhere comparable and not here. " +
		"`expectations` reports an entry point missing an authorization control most of its comparable peers apply; same origin and same limits as CWE-306. " +
		"`sibling-guard-differential` narrows that from a population to a PAIR, which is what it takes to say something about two handlers on one resource rather than about a whole surface: a value read out of the request by two functions in one module, passed by the READ path to a call that asks a question about it -- validate, verify, authorize, hasAccess, belongsTo -- and by the WRITE path beside it to nothing of the kind. The finding cites the sibling, because the engine cannot know what check ought to be there and does not have to: the program wrote one, one function away, over the same value. " +
		"The direction is fixed and that is the whole of what keeps it quiet. A write that checks more than a read is the ordinary asymmetry of every application and is evidence of nothing; the inversion is what no design explains. Measured: the unrestricted form of this comparison -- guard sets differ between two verbs of one handler class -- produced 32 candidate pairs in jupyterhub alone, and reading them showed why, since a GET has no body to validate and a DELETE has no model to check. Four conditions cut ten repositories to three findings, all true, all unleash's variants controller, where the GET calls `validateFeatureBelongsToProject` and the patch, overwrite and push paths take the same `featureName` and `projectId` out of the same request and do not: the value must be one the caller chose, read off a request parameter; the direction must be read-checks-write-does-not; the weak path must hold every value the check consumed, because a check it has no arguments for is a different question rather than a missing one; and the weak path must do something with the value other than log it. " +
		"The first of those four conditions was stated and not enforced, and measuring the rule again across ten production repositories showed what that cost: seven findings, none of them judged worth reporting, every one anchored on something no caller picked. The anchor is now required to be a value the caller chose. The request CONTAINER is refused because it is not a value -- it is every field the caller sent together with whatever the framework hung on it, so two functions that both take it have nothing in particular in common and a call handed the whole request has been asked a question about nothing. Saleor's graphql/context.py was three of the seven on exactly that: the functions that BUILD the request's identity, compared against the get_user that reads it, with `authenticate(request=request)` counted as an authorization guard they had skipped -- and a function that PRODUCES the identity cannot be required to have already consumed it. A part the SERVER wrote is refused for the second reason: `request.user` is the authentication layer's answer about who is calling, so a handler consulting it has named no resource and one that does not has skipped nothing a caller could choose, which was the other four in paperless-ngx. The parts named are the four the corpus holds -- user, auth, app, session -- and deliberately not cookies or headers, which the caller writes. " +
		"What it does not catch is most of the shape it is named for. A check supplied further down a call chain the frontend could not resolve is invisible: unleash's `deleteFeatureStrategy` looks identical to the three real ones and is protected three frames away inside `unprotectedDeleteStrategy`, and it is excluded here only because the value's one visible use in the handler is a log line -- an accident, not a judgement, and the next case of that shape will report. Two handlers whose check turns on no shared request value are not compared at all, which loses jupyterhub's OAuth pair, where the GET authorizes access to the client and the POST does not but nothing the caller sent anchors the difference. A bulk endpoint and its single-item twin are not compared, because the bulk path reads a list from the body and the single path a name from the route, and those are not the same value under any spelling -- jupyterhub's user-create is that, and stays a miss. And the check must be named like one: a guard spelled as a bare comparison, or as a helper with a name that says nothing, is not recognised" +
		"`control-omitted-on-sibling-path` is the third, and it is the only one that can say a control is missing while the CONTROL IS RIGHT THERE. The other two report an absence across handlers; this reports a hole in the coverage of a control the program applies, on a path beside one it stands on, where both paths end at the same operation on the same record. Convergence is the whole of the difference from CWE-306. That rule cannot tell an endpoint that is public by design from one that forgot -- medplum mounts a public FHIR router beside a protected one deliberately, and it was reported until the design said otherwise -- and this one is not asked to: two paths that produce the same value and hand it to the same call cannot have been meant to differ in who may take them. A public route beside a protected one shares no value and no sink and is never paired. " +
		"Two enumerations of `beside`, because real programs spell it two ways. BRANCH: two arms of one function that both assign the record and both reach the operation, where the check dominates only one arm -- archivebox's snapshot view asks `can_view_snapshot` on the id branch, takes the url branch straight out of an unfiltered queryset, and both arms fall through to one canonical redirect. PEER: sibling methods of one class performing the SAME call on values out of the SAME parameter, where two of them gate it and one does not -- paperless-ngx's status consumer calls `_can_view(event['data'])` before `self.send` in two handlers and sends unconditionally in `documents_deleted`. Two agreeing peers rather than one is the safety margin: one handler differing from one other is the ordinary asymmetry of every application, and only a convention with a hole in it can be cited. " +
		"Measured over ten production repositories the rule added two findings and both are the real ones, and each of the four narrowings that made that true was paid for by findings it removed. A RETRIEVAL is not an operation: `self.get_serializer(request.data)` appears in twelve unrelated view classes of one paperless-ngx module and taking it for an operation made every one a peer of every other -- twelve false findings, all gone. A value stops being the parameter after two hops: followed further, every value in a handler descends from `request`, and unlimited following paired `Response(meta)` with `Response(resp_data)` six hops down two different document lookups -- three more, all gone. A decision is recognised on the LEAF of the name, because `client.createAuthorizationURLWithPKCE` starts with `client` and a prefix test on the whole expression answers a question about the receiver -- documenso's CSC OAuth builder, three more, all gone. And the peer group is keyed on the parameter list as well as the module, because the IR names no class and a four-thousand-line views module is otherwise one group. " +
		"What it does not catch is the same thing everything else here misses and one thing more. A control applied inside a helper the frontend could not follow reads as no control at all, and the four false findings above were all of that kind before the narrowings -- paperless's `metadata()` is protected by a `_resolve_request_and_root_doc` that returns a forbidden response, and no narrowing SAW that; they were removed for other reasons and the shape will report again. A branch whose record has one definition -- assigned once above the check and merely used differently below -- is not a sibling path and is not compared. A check whose name says nothing is invisible, as it is for every rule in this family. And the peer form requires two agreeing peers, so a class with exactly two handlers, one guarded and one not, is a deliberate miss",
		By: []string{"expectations", "sibling-guard-differential", "control-omitted-on-sibling-path"}},
	// Fail-open is a Class and therefore outside the denominator, but a rule that finds it
	// has to be claimed by something or the coverage map takes no credit for it.
	"CWE-636": {State: Partial, Reason: "a restriction the program built and then left behind. `discarded-restriction` reads the hole in a control's coverage from the far end: not an operation the check does not stand on, but an EXIT taken from a path on which the check was already being accumulated, from which the point that applies it is not reachable. medplum's `addAccessPolicyFilters` is the measured case -- it pushes a compartment condition into `expressions`, then meets an access policy whose criteria name the wrong resource type, logs `Invalid access policy criteria` and returns, and the `builder.predicate.expressions.push(new Disjunction(expressions))` twenty-five lines below never runs. The function returns nothing, so the restriction it attaches is its only product and leaving without attaching it does not narrow the search: it widens it. " +
		"The complaint is not decoration, it is the rule's whole precision. Nine lines below the reported return, the same loop over the same accumulator returns again on the no-criteria branch, and that one is correct -- a policy naming no criteria allows everything, so a disjunction with an already-satisfied term is rightly dropped. NOTHING IN THE GRAPH SEPARATES THEM. What separates them is that one of them records that something is wrong first, and a control that gets weaker on the branch where something is wrong is the weakness. Measured over ten production repositories the rule fired once, on that function, and the unconditioned form fired twice there and was right about half. " +
		"What it does not catch. A bare early return, by construction and by the paragraph above. A `throw`, deliberately: raising propagates the refusal and the caller's query is never built, so nothing is left open. A function that RETURNS something, because an early return from one is answering its caller rather than abandoning its work -- which loses the same defect written as `return expressions` on some paths and not others. And the accumulator has to be named for what it is: the engine cannot know what an array of conditions is FOR, and the function that builds it and the name it is built under are the only statements of intent the source contains",
		By: []string{"discarded-restriction"}},
	"CWE-434": {State: Partial, Reason: "an uploaded file stored at a destination the caller named, which is how the caller ends up choosing the stored type. Matched on the receiver rather than the method name -- `save` and `mv` belong to every ORM record in a program, and only an upload's is called on data that arrived in the request. Partial for two reasons: the confining validation is an extension allowlist, and no shape of one is modelled yet, so a handler that checks properly still reports; and the multer-plus-fs.writeFile shape reports as CWE-22 instead, because there the untrusted value is a filename and the sink is an ordinary file write",
		By: []string{"untrusted-to-stored-file-type"}},
	"CWE-476": {State: Undecidable, Reason: "in these languages this is a TypeError on undefined at runtime rather than a memory fault, and deciding it statically means proving nullability across a dynamic language; the value even when solved is reliability rather than security"},
	"CWE-770": {State: Partial, Reason: "six rules, and what they have in common is that the program itself supplies the evidence. `expectations` reports an entry point missing a throttle most of its comparable peers apply. " +
		"`unbounded-retention-by-caller-key` reads the KEY a write was filed under rather than the value: a container reached through a binding no request created gains one entry per distinct key, so when the caller chooses the keys, no comparison anywhere measures the container against a number written in the source, and no lookup of that key has DECIDED anything before the write, the number of entries the process keeps is a number the caller sets -- uptime-kuma installs an UptimeCalculator in a process-wide map for whatever monitor id arrives, in the same basic block as the call asking whether that monitor is public and two lines before the answer is read. " +
		"`refusal-inside-a-repeating-callback` is the same judgement the rejection rule makes about a block, made about a callback: a size limit enforced from inside a listener for an event that happens AGAIN is a limit the program measures and does not apply, because a return detaches nothing and the next chunk is appended to the very buffer the limit was about -- linkwarden's migration endpoint. " +
		"`expensive-entry-outside-rate-limiter` first requires a mounted bucket-consuming control, then reports only an entry point outside that control's path or request predicate when the entry reaches an outbound request, subprocess or query; this is deliberately stronger than claiming every expensive route in every application needs a limiter. `rate-limit-key-from-trusted-forwarding-header` compares express-rate-limit's default req.ip key with the application's own trust-proxy declaration, and speaks only where the library's validation is explicitly disabled and no key generator replaces the default. " +
		"`rate-limit-key-from-a-client-supplied-header` is that rule's other half and exists because that rule keys on a LIBRARY and a FRAMEWORK SETTING rather than on the key. reactive-resume builds its bucket key out of the first of five forwarding headers it finds, sets no Express trust anywhere and limits with a package the constructor list has never heard of, so the configuration rule had nothing to match while the weakness was identical. This one asks three questions of the graph instead: the module constructs a rate limiter, by a word in the call's name; a function in it is that limiter's key, by the option it was written under; and that function reaches a read of a forwarding header. Its stated cost is a deployment whose proxy OVERWRITES the header rather than appending to it, which no static reading can distinguish -- the same irreducible uncertainty the configuration rule accepts, with one piece of evidence more, since a header read into the thing that decides a bucket is being trusted rather than recorded. It also carries a stated limitation of the engine rather than of the rule: neither frontend links an imported constant to the module that declares it, so the header list is resolved by name at module scope inside this analysis alone. " +
		"Measured over ten production repositories the six rules added five findings and all five were true: the two previously recorded retention/listener findings, searxng's autocomplete route outside its /search limiter, unleash's forwarded-address bucket key, and reactive-resume's X-Forwarded-For bucket key. " +
		"What they do not catch is stated. A basic block is the whole evidence for the lookup question, so a write inside a LOOP BODY or a switch arm -- where neither frontend states a position, deliberately -- is passed over rather than guessed at. A container IMPORTED from another module has no value in this IR, so the write into it records no destination and nothing is judged; the container has to be declared in the module the write is in, which is where uptime-kuma's is. A cap is only recognised where the extent is measured against a number written down: `cache.size > MAX_ENTRIES` through a constant is not matched and will suppress nothing, and the bias there costs recall rather than precision. A key that arrives through a call the frontend could not resolve carries no classification and is not a key the caller chose as far as this rule can tell -- linkwarden's bulk endpoints are invisible for exactly that reason, because its `@/...` path aliases resolve to no module. And the ITERATION half of this weakness is not built at all: see CWE-834",
		By: []string{"expectations", "unbounded-retention-by-caller-key", "refusal-inside-a-repeating-callback", "expensive-entry-outside-rate-limiter", "rate-limit-key-from-trusted-forwarding-header", "rate-limit-key-from-a-client-supplied-header"}},

	"CWE-1336": {State: Partial, Reason: "untrusted data reaching a call that COMPILES a template. Every engine described here exposes property access and method calls to the template text, which is why this ends in code execution rather than in mangled markup. A template loaded from disk and rendered WITH untrusted data is not this weakness and is not reported",
		By: []string{"untrusted-to-interpreter", "upstream-response-to-interpreter"}},

	"CWE-611": {State: Partial, Reason: "untrusted data reaching an XML parser that resolves external entities. The two libraries described have opposite defaults and are treated accordingly: libxmljs resolves only when the call passes `noent`, so the call is read for it, while lxml's default parser resolves and is named outright. Nothing is claimed about parsers that are safe by default and can be made unsafe by configuration this engine cannot see",
		By: []string{"untrusted-to-xml-parser", "upstream-response-to-interpreter"}},

	"CWE-915": {State: Partial, Reason: "the caller's object handed to a record writer WHOLE rather than field by field, which is a question about structure in the same way SQL injection is a question about text: a value that became a FIELD of something is not the caller's object. Matched only where the symbol leaves no room for doubt. `update`, `create` and `save` were tried and withdrawn -- `save` is what an uploaded file is written with, `update` is already how a record is selected by its identifier, and a dictionary has all three -- so ORM-specific spellings of this weakness are a stated miss",
		By: []string{"untrusted-to-record-fields"}},

	"CWE-916": {State: Partial, Reason: "a password-hash work factor written into the call and below the floor at which it does any work worth the name. Reported and never gating: a work factor is only too low for a LOW-ENTROPY input, and the call does not carry what it was given -- deriving a key from an already-random secret with a small count is correct and reads identically. Deciding it properly means knowing the input is a password, which is a flow question this kind cannot answer alone. The thresholds are floors and deliberately not current guidance -- bcrypt at 10 is the library default -- because a rule that fired on current guidance would fire on every codebase forever and be switched off. A work factor read from configuration is not a number in the call and is not matched. " +
		"`password-verified-by-plain-digest` is the same weakness written the other way round -- no work factor at all -- and it is judged at the COMPARISON rather than at the call, because that is where the program says what the digest was for: a digest classified as broken against collision, tested against a value whose name says the program stores it as a password. It arrived by measurement. The collision rule reported mitmproxy's htpasswd verifier and an independent reader was right to reject it, since finding two inputs that hash alike gives nobody a password for a digest they did not choose -- but the line is wrong anyway, and reporting the wrong number on a real weakness is how a reader learns to stop reading. Scoped to the digests already classified broken, which is narrower than the weakness: a password verified against an unsalted SHA-256 is exactly as wrong and is not matched, because the class that would carry it also carries HMACs and random bytes and an HMAC of a password under a server-held key is a different construction. The stored side is read through an anonymous subscript, so `pwhash[5:]` past an htpasswd format prefix is still `pwhash`",
		By: []string{"weak-password-hash", "password-verified-by-plain-digest"}},
	"CWE-329": {State: Partial, Reason: "an initialisation vector written into the source, matched on having been written down rather than on what it says, exactly as a hardcoded key is. An IV must be unpredictable and must never repeat, and one in the source is both predictable and reused on every message",
		By: []string{"predictable-iv"}},

	"CWE-470": {State: Partial, Reason: "untrusted data naming a module for the runtime to load, which runs it. Requires a WHOLE value, which is a trade rather than a safety argument: `require(\"./handlers/\" + name)` is what every plugin loader looks like and reporting them all would make the rule unusable, but a leaf containing `../` escapes the fixed directory and is missed",
		By: []string{"untrusted-to-interpreter", "upstream-response-to-interpreter"}},
	"CWE-1321": {State: Partial, Reason: "the caller's object merged into another by a function that walks NESTED keys, so a `__proto__` key in it reaches the prototype every object inherits from. The named deep-merge helpers only; a merge written by hand is a loop over keys and is not matched",
		By: []string{"untrusted-to-record-fields"}},

	"CWE-378": {State: Partial, Reason: "tempfile.mktemp(), which hands back a name without creating anything and has no safe calling convention. Only that one API; a temporary file created insecurely by hand is a stated miss",
		By: []string{"insecure-temp-file"}},
	"CWE-276": {State: Partial, Reason: "a file or directory mode written into the call with the world-writable BIT set, which is the actual rule rather than a list of bad numbers -- 0o777, 0o666 and 0o1777 are wrong for the same reason. A mode computed at runtime is not matched",
		By: []string{"world-writable"}},

	"CWE-88": {State: Partial, Reason: "untrusted data reaching an element of a Python process argument list where it may be parsed as an option. A literal end-of-options separator, a value proven not to begin with a dash, and programs explicitly known to have no option surface are excluded; commands outside the described subprocess APIs are a stated miss",
		By: []string{"untrusted-to-interpreter", "upstream-response-to-interpreter", "process-argument-to-argv"}},
	"CWE-1236": {State: Partial, Reason: "untrusted data written into a CSV a spreadsheet will later interpret, where a cell beginning with a formula character runs on the machine of whoever opens it. The named writers only, and nothing is claimed about whether the application prefixes cells to defuse them, because no such convention is modelled",
		By: []string{"untrusted-to-spreadsheet"}},

	"CWE-497": {State: Partial, Reason: "the process environment reaching a response body or an outbound request WHOLE. One variable published on purpose is ordinary and is not reported: the classification is the environment itself, not anything read out of it, and a value that was projected on its way to the sink is excluded again there. Only the environment; a configuration object an application builds itself is not described. Claimed at STARTUP as well as in a handler, which is where reading the environment actually happens: the top level of a module the language designates as a program start is an entry point, and everything it reaches is startup code. Two call-graph facts are what make that worth anything and both are stated because either missing makes the claim empty -- an attribute chain deeper than one segment resolves to a definition the program holds, so `app.Hub.launch()` in a `__main__` guard does not call out of the program; and a function handed to something else as an ARGUMENT is followed, in both directions, so `run_sync(partial(self.start_async))` does not end the chain. Reported at warning and never gating: an operator started the process",
		By: []string{"environment-outward"}},

	"CWE-532": {State: Partial, Reason: "a credential the CALLER sent reaching a log. The name list decides a classification over request PATHS rather than over local variable names, which is the whole reason it works: matching credential-shaped locals was measured across twenty clean repositories first and every match was a counter of language-model tokens. A one-way hash ends the classification, because a password hash is not a password anywhere. Credentials the application holds rather than receives are not covered, and the named loggers only",
		By: []string{"credential-recorded"}},

	// The parent of every disclosure entry in the catalog. What counts as sensitive
	// information is a judgement about the data, and this engine makes that judgement
	// under the numbers that name the data rather than under the parent.
	"CWE-200": {State: NotBuilt, Reason: "information exposed to somebody who should not have it. Every decidable form of it is claimed under the number that names the DATA -- credentials under CWE-522, failure detail under CWE-209, the process environment under CWE-497, personal information under CWE-359 -- because what makes information sensitive is what it IS, and a rule for the parent would have to decide that without being told. One form that needs no such judgement was BUILT AND WITHDRAWN: the framework announcing itself in an X-Powered-By header, which is decidable from the source and fixed in one line. It measured three of the four Express applications on the vulnerable corpus against four of the ten across twenty-eight production repositories -- the worst ratio of anything shipped -- for a header a reverse proxy strips routinely, and it put a finding into every one of 55 fixtures that constructs an Express app. A rule has to earn its noise"},
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
	"CWE-347": {State: Partial, Reason: "signature verification switched OFF by name in the call, including where the option sits inside a nested dict -- PyJWT's options={\"verify_signature\": False} was a stated miss until options one level down were read, and it is where four of the seven clean-corpus findings turned out to be. PyJWT's older `verify=False` is covered too, narrowed by the METHOD being decode rather than by a companion `algorithms` keyword -- the qualifier used to be `the call also names algorithms`, which is what a JWT decode usually carries and not what it must, and the one in the vulnerable corpus carries none. Matching decode() with no flag at all was tried and withdrawn: reading a token to look at it is ordinary and 58 sites across the clean corpus do exactly that. Reported and never gating for the same reason at one remove -- capping an expiry or routing on an issuer needs no verification, and what makes an unverified decode a defect is whether the claims are then believed, which the call does not carry",
		By: []string{"unverified-signature"}},
	"CWE-259": {State: Partial, Reason: "a password written into the source as the option of a call that OPENS A CONNECTION, matched by option name rather than by argument position because that is how every such library asks for one. Scoped to those calls deliberately: matching any call with a password option was tried and produced 265 findings across the clean corpus, almost all test helpers and assertions. A password read from the environment is not a literal; an option whose key is known while its value was not written down is treated as absent",
		By: []string{"hardcoded-password"}},
	"CWE-297": {State: Partial, Reason: "a TLS connection told not to check the certificate's hostname, which accepts any valid certificate rather than the one belonging to the host being talked to. The literal keyword only",
		By: []string{"no-hostname-check"}},

	"CWE-90": {State: Partial, Reason: "untrusted data COMPOSED into an LDAP filter, where a `*` in the wrong place turns a check for one user into a match for any. Composition is required to keep the rule precise on the common shape, and unlike SQL it costs a real miss: an LDAP filter ARGUMENT passed whole is the whole filter, not a parameter, so the caller writing all of it is not reported",
		By: []string{"untrusted-to-interpreter", "upstream-response-to-interpreter"}},
	"CWE-643": {State: Partial, Reason: "untrusted data composed into an XPath expression, which selects whichever nodes the caller names rather than the ones the application meant. The named evaluation APIs only",
		By: []string{"untrusted-to-interpreter", "upstream-response-to-interpreter"}},
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
	"CWE-155": {State: Asserted, Reason: "caller data reaching an API that interprets its argument as a WILDCARD PATTERN rather than as a name. `**/*` walks the whole tree from wherever the program started and a character class reads names the caller was never offered, and the two are not the same weakness as choosing a path -- which is why they are reported apart. Narrow and unambiguous on purpose: the symbol says the argument is a pattern, and the language ships `glob.escape`, which the engine records as clearing it",
		By: []string{"untrusted-to-glob"}},
	"CWE-91": {State: Asserted, Reason: "caller data BUILT INTO an XML document rather than carried by one. The composition is the whole evidence and it is the same evidence SQL injection rests on: a caller who is concatenated into the syntax can write the syntax. Parsing a document a caller SENT is a different question entirely, judged by what the parser is configured to do and claimed under CWE-611. `xml.sax.saxutils.escape` is recorded as clearing it",
		By: []string{"untrusted-into-xml"}},
	"CWE-253": {State: Partial, Reason: "a verification result read as a STATUS CODE. `crypto.verify(...) === 0` is how a C programmer checks a return value, and in these languages the call answers true or false -- so the check inverts and a signature that failed reads as one that passed. Only the named verification calls, and only against a small number written in the source. The broader weakness is not built and the reason stands: both runtimes signal failure by RAISING rather than by returning a code, so a status nobody looked at is not how errors travel here",
		By: []string{"boolean-compared-to-number"}},
	// BUILT AND WITHDRAWN, which is why the reason is this specific.
	// Unbounded iteration, measured and withdrawn. Recorded here rather than left as an
	// empty space, because the reason it is not built is a fact about the IR that the
	// next attempt needs.
	"CWE-834": {State: NotBuilt, Reason: "a loop whose trip count a caller decides. The rule remains deliberately not built: the earlier attempt was withdrawn when neither frontend carried repetition, and the fact-only change did not retry it. Its two structural prerequisites now exist in IR 0.18. Both frontends mark a loop header, emit the ordinary successor that returns to it, and attach the value whose extent or truth decides another iteration; `internal/cfg.Repetitions` returns every enclosing cycle and its stated bound. A computed comparison operand carries arithmetic provenance too, so `num > 24 * 30` is a comparison rather than disappearing. " +
		"The production obstacles recorded by the withdrawal do not become rules by acquiring these facts. linkwarden's bulk controller is still unreachable through its unresolved `@/lib/...` path alias, and uptime-kuma's switch arms remain straight-line. Reaching-definitions also keeps loop-body flows unplaced: narrowing that conservative refusal is a separate measurement, not a side effect of emitting repetition. " +
		"Measured over all 149 corpora, the six fixtures containing source loops gained 11 bounded headers across 10 functions and 33 blocks while every corpus remained at precision 1.00 and recall 1.00. Findings were byte-identical before and after on all ten production clones. testdata/unbounded-resource carries the discriminator for a later rule attempt: a caller collection capped by a computed constant, a collection the program wrote down, and a caller collection with no numeric cap",
	},
	"CWE-1024": {State: NotBuilt, Reason: "a comparison between values that cannot be equal. The decidable form is a call the language guarantees a boolean from compared with something that is not one -- `Array.isArray(x) === \"true\"` -- and a rule for it was written and withdrawn, because the only realistic spelling compares against the STRING \"true\", and the engine deliberately does not treat \"true\", \"false\" or \"null\" as text: an identity check against one of those is a flag test, which is a different rule that would break if this one were accommodated. Every other form needs both operands typed, which neither frontend can do -- the Python one has no inference at all"},
	"CWE-1077": {State: Asserted, Reason: "a comparison with NaN, which is false however it is written -- the inequality included, because NaN is not equal to itself either. A branch that tests for one is a branch that never runs, and in a check that is not a check. Matched on the NAME rather than on a literal, because the language provides the value and there is nothing written down to read. Only the equality operators: an ordering comparison with NaN is also false and is far more often a deliberate sort guard",
		By: []string{"compared-to-nan"}},
	"CWE-183": {State: Partial, Reason: "an origin or a referrer checked against an allow-list by prefix, suffix or containment rather than by equality. The list is right and the comparison is too generous, which is the harder half to see: a prefix match accepts https://example.com.attacker.net and a suffix match accepts https://notexample.com, and both pass a check that reads as correct. Deliberately scoped to the ORIGIN class rather than to caller data in general, and the difference was measured: a partial match on any untrusted value whose result the function RETURNS -- which is what a validation predicate looks like -- occurs 1332 times across twenty-eight production repositories against 61 on the vulnerable corpus, and most of them are `find` and `endsWith` on file names and node types. What separates a bypass from a filter is whether the boolean GATES the operation, and this engine does not model guards. Only where the string being matched is one the caller SENT, which the dataflow already answers; an allow-list checked against something else is not this weakness. Clean corpus: zero",
		By: []string{"permissive-origin-match"}},
	"CWE-208": {State: Partial, Reason: "the non-constant-time-secret-comparison rule requires two independently established sides: one value is caller-supplied, and the other is a runtime secret or digest classified by HMAC/hash/random provenance or by a secret/token/signature/digest property leaf. Neither language promises constant-time equality, so `==`/`!=` leaks how much of the guess was right. A literal is excluded as a presence check, flag test, or CWE-798 hardcoded credential; two values the same caller sent are excluded as a confirmation field. `hmac.compare_digest`, `secrets.compare_digest`, `crypto.timingSafeEqual`, and `django.utils.crypto.constant_time_compare` are calls and leave no equality operator to match. What it does not catch: an application-secret local with neither classified provenance nor a role-bearing property name, a comparison hidden inside an application helper, or a timing difference caused by work other than equality",
		By: []string{"non-constant-time-secret-comparison"}},
	"CWE-732": {State: Partial, Reason: "the secret-file-created-before-chmod rule joins a Python file lifecycle only when a reachable function opens one path in a creating builtins.open mode, writes through that exact handle, and later chmods the same path to 0o600. The late chmod is the program's own evidence that the file is private; ordinary created files are silent. It does not catch a private mode other than exactly 0o600, a handle/path relation hidden behind a helper, a mode computed at runtime, a file API other than builtins.open plus os.chmod, or failure of chmod as a second weakness. An `opener=` is treated as explicit creation and is silent, as are os.open and NamedTemporaryFile spellings",
		By: []string{"secret-file-created-before-chmod"}},
	"CWE-129": {State: Partial, Reason: "the regex-capture-arity-not-checked rule proves a JavaScript regex literal has fewer capture groups than a numeric index read from its exec/match result. Escaped parentheses, character classes, noncapturing groups and lookarounds do not count; named captures do. It does not catch an in-range capture read before checking that the match succeeded, a dynamic or constructor-built regex, destructuring, a computed index, Python's string-pattern regex API, a read in unmodelled control flow with several candidate definitions, or the downstream security consequence of the always-undefined value",
		By: []string{"regex-capture-arity-not-checked"}},
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
	"CWE-488": {State: Partial, Reason: "one request's data assigned to a name bound outside the handler, which every later request reads back. The language rule is the whole evidence and there is no guessing in it: Python needs the name declared global and JavaScript needs it bound in an enclosing scope, and the same statement without either makes a local and touches nothing. A value stored in a module-level CONTAINER -- a dict, a Map -- is a cache and is not matched. The container and shared-depletable-resource extension was BUILT AND WITHDRAWN after measurement. The broad fact the IR can state -- one module-rooted receiver used by multiple entry points -- produced 41 resource groups and 302 calls across ten repositories; restricting it to state-changing and depleting method names still left 6 groups and 17 calls, all in uptime-kuma, with no fact distinguishing the harmful login/logout pair. Both are remote event consumers with no recorded control, so receiver name would be the entire judgement. The other named site is not recoverable by this rule: searxng lowers `_custom_query` and both writes, but the dispatch-table reference produces zero call sites and no enumerated entry point reaches the function. Reporting it would require treating an arbitrary unreached parameter as caller data. Both choices buy a known site by asserting what the IR does not know, so neither ships",
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
	"CWE-613": {State: Partial, Reason: "a credential cookie whose lifetime is written into the call and is longer than a month, and a jsonwebtoken.sign call where every possible home of an expiry is enumerated and neither `exp` nor `expiresIn` is present. An inline payload makes an omitted options argument knowable; a payload built elsewhere is silence, because its claims are not visible. Test-only issuance is excluded: a token a test creates for itself has no deployment lifetime. Only cookies whose NAME says they carry a credential are asked about, because a year-long theme preference is a feature. Thresholds are per-rule rather than per-keyword, because express counts milliseconds and Flask counts seconds under names that look the same. A lifetime computed at runtime, a server-side session store expiry, and a verifier's missing maxAge when the issuer cannot be paired are not decidable here. Measured across ten production repositories the newly knowable omitted-options shape added one finding, uptime-kuma's authentication token; its inline payload has no exp and the corresponding verify supplies no maxAge",
		By: []string{"long-lived-session", "unexpiring-token"}},
	"CWE-1022": {State: Partial, Reason: "a window opened onto a named target with no third argument, which is where noopener would be -- the opened page keeps a live reference back through window.opener and can navigate the page behind it. Only the scripted form: markup written as a template string is text to this engine and its attributes are not read",
		By: []string{"opener-reachable"}},
	"CWE-1021": {State: Partial, Reason: "framing protection switched off by name in the call. Only an explicit disable: an application that never sets the header at all is not reported, because absence would have to be judged program-wide and the engine cannot see middleware it has no model for",
		By: []string{"frames-allowed"}},

	// Two weaknesses this engine finds and reports under a SIBLING'"'"'s number. Recorded as
	// not built rather than claimed, because a coverage map is read by someone looking
	// for findings carrying that identity, and none ever will.
	"CWE-256": {State: NotBuilt, Reason: "a password stored in plaintext. BUILT AND WITHDRAWN: a caller's password reaching an ORM create, save or insert. Sound in principle and wrong in practice, because ORMs hash in a lifecycle hook the engine cannot connect to the insert -- wikijs writes `password: req.body.adminPassword` into an Objection insert and hashes it with bcrypt in a $beforeInsert on the model, which is correct code and the only finding the rule produced on the clean corpus. The vulnerable corpus writes passwords through constructors and raw SQL, which this shape does not reach either, so it cost a false positive and bought nothing. What the engine DOES find is a credential reaching a file, reported as CWE-312"},
	"CWE-523": {State: Subsumed, Reason: "credentials sent without transport protection. Caught by the rule for CWE-319 and reported under that number, which names the same line by its scheme rather than by its payload -- one line, one fix, and a reader told about both would be told the same thing twice",
		By: []string{"credential-in-cleartext"}},

	// CONSIDERED AND DECLINED for a reason that is not a measurement: either another
	// number already carries the finding, or the evidence the weakness turns on is not in
	// the source at all.
	"CWE-838": {State: NotBuilt, Reason: "a value escaped for the wrong context -- URL-encoded and then written into markup. The engine already knows this: a transform that does not clear the sink's context is recorded in the evidence with clears=false, and the finding is reported under the identity of the weakness the transform FAILED to prevent, which for markup is CWE-79. Reporting it under this number instead would trade a name the reader can act on for one that describes the mechanism"},
	"CWE-829": {State: Subsumed, Reason: "functionality included from somewhere the application does not control. Caught in its two decidable forms and reported under theirs: the caller naming a module for the runtime to load is CWE-470, and code fetched over the network and piped into an interpreter is CWE-494. The parent adds no line either of those misses",
		By: []string{"untrusted-to-interpreter", "unverified-download"}},
	"CWE-96":   {State: NotBuilt, Reason: "caller data written into a file that is later executed as code. Two artifacts and two moments: the write is here and the execution is elsewhere, usually in another process and often in another language, and nothing in one source tree links them. What IS decidable -- data reaching an interpreter directly -- is CWE-95"},
	"CWE-215":  {State: NotBuilt, Reason: "sensitive information in debugging code. Both halves are already claimed and reported: a credential or system fact reaching a log is CWE-532 and CWE-497, and a debug server started with debug enabled is CWE-489. What this number adds is the judgement that the code was DEBUG code, and a logger called debug is not evidence of that -- production systems log at debug level on purpose"},
	"CWE-1295": {State: NotBuilt, Reason: "the same shape as CWE-215 and the same answer: what reaches the message is claimed under CWE-209 and CWE-497, and whether the message was unnecessarily detailed is a judgement about intent"},
	"CWE-212":  {State: NotBuilt, Reason: "sensitive information not removed before something is stored or sent. The engine reports what it can SEE reaching a destination -- CWE-201 for sent data, CWE-312 for stored -- and this number is about what should have been taken out, which requires knowing what the record was supposed to contain"},
	"CWE-535": {State: Subsumed, Reason: "a shell error message exposed. Caught by the rule for CWE-209 wherever the message reaches a caller, which is the same judgement over a message this engine cannot tell came from a shell",
		By: []string{"internal-detail-outward"}},
	"CWE-379": {State: Subsumed, Reason: "a temporary file created in a directory anyone can write to. Caught by the rule for CWE-378, its sibling, which finds the calls that make one; what would distinguish this entry from that one is the directory's permissions, which are a fact about the machine rather than about the source",
		By: []string{"insecure-temp-file"}},
	"CWE-540": {State: NotBuilt, Reason: "sensitive information in source code. Its one decidable form -- a credential written into the source -- is CWE-798, and this engine reports 135 of them across the clean corpus under that number. What is left is internal hostnames, paths and comments, where nothing in the text says whether publishing it matters"},
	"CWE-626": {State: NotBuilt, Reason: "a null byte truncating a path or a name. Both frontends target runtimes that reject an interior null in a path outright -- Node throws, Python raises -- so the interpretation this weakness depends on does not happen"},
	"CWE-332": {State: NotBuilt, Reason: "insufficient entropy in a PRNG specifically. The rule this engine has asks whether a random value was long enough and does not ask what produced it beyond the symbol, so a generator that is weak for a reason other than its length is not seen. Its sibling CWE-338 covers the generator being the wrong KIND"},
	"CWE-546": {State: NotBuilt, Reason: "a comment that admits something. Comments are not in the IR at all -- the frontends lower code -- and a TODO is a note about work rather than a defect in it"},
	"CWE-615": {State: NotBuilt, Reason: "sensitive information in a comment. Same reason as CWE-546: comments are not lowered, and adding them would mean matching secrets in prose, which is the least reliable rule this project could ship"},
	"CWE-625": {State: NotBuilt, Reason: "a regular expression that permits more than it should -- typically one missing its anchors, or one whose unescaped dot lets `example.com` match `exampleXcom`. The engine cannot tell a validating match from a searching one, and an unanchored pattern is exactly right for the second. The sharper half was counted rather than assumed: across twenty-eight production repositories 3688 patterns look like they match a host or a URL and 728 of them contain an unescaped dot, against 13 on the vulnerable corpus -- and the 728 are display patterns, documentation URLs and log parsers, where a dot matching any character costs nothing. Regular expression literals are not lowered either, so this would need a frontend change before it could even be tried"},
	"CWE-367": {State: NotBuilt, Reason: "a check and a use separated in time. The shape is visible and was counted: 44 sites across twenty-eight production repositories where a program tests a path and then opens it, against 3 on the vulnerable corpus -- and the 44 are CLI installers, log rotators and configuration loaders doing exactly what `if exists then read` is for. What makes the pair a weakness is not in the source at all: whether anything else can write that path between the two calls is a fact about the directory's permissions and about what else runs on the machine"},

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
		ids:    []string{"CWE-190", "CWE-191", "CWE-192", "CWE-193", "CWE-197", "CWE-369", "CWE-681", "CWE-1335", "CWE-1339"},
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
		ids:    []string{"CWE-112", "CWE-130", "CWE-150", "CWE-182", "CWE-183", "CWE-233", "CWE-289", "CWE-304", "CWE-322", "CWE-325", "CWE-335", "CWE-394", "CWE-397", "CWE-474", "CWE-549", "CWE-1173"},
	},
	{
		reason: "a path-interpretation defect: two spellings of one location, or a link that points somewhere else. This engine reports the caller CONTROLLING a path (CWE-22 and CWE-73) and never inspects the path's CONTENTS, which is what would distinguish these -- and the answer depends on the filesystem the code is running on rather than on the code",
		ids:    []string{"CWE-41", "CWE-66"},
	},
	{
		reason: "a bound the caller chose, used as an index, a length or a limit. Structurally out of reach rather than merely unbuilt: a request value has to become a NUMBER before it can be one of those, and the numeric conversions are one-way transforms that end the classification -- correctly, since a number cannot carry syntax. What remains is a question about magnitude, which this engine does not model. The allocation form is claimed under CWE-789",
		ids:    []string{"CWE-129", "CWE-1284", "CWE-1285"},
	},
	{
		reason: "an unchecked or misread return value. Both runtimes signal failure by raising rather than by returning a code, so the shape this weakness describes -- a status nobody looked at -- is not how errors travel here. A discarded promise is the real local form of it and is a correctness question rather than a security one",
		ids:    []string{"CWE-252"},
	},
	{
		reason: "a TRUSTED module-level variable initialised from outside. The caller's data reaching process-wide state is claimed under CWE-488; what this number adds is the judgement that the variable was one the program later trusts, and the source does not say which module-level variables those are",
		ids:    []string{"CWE-454"},
	},
	{
		reason: "a security-relevant constant living somewhere this engine does not read, or one whose significance the source does not state. Configuration files, environment templates and deployment manifests are not source and are not lowered; and a constant that is security-relevant reads exactly like one that is not",
		ids:    []string{"CWE-547"},
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
