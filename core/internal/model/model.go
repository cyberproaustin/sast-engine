// Package model holds the security model the core matches against the IR.
//
// The vocabulary is deliberately about PROPERTIES, not defects (ADR-012). A value has
// a data class because of where it came from. A channel has a visibility and a context
// because of what it is. A policy forbids a pairing of the two. A defect is what
// happens when a policy is violated — it is never something the model names directly.
//
// This is what lets one small rule set find instances nobody enumerated: credentials
// in a log, internal detail in a response body, request data in a shell command, and
// PII in an outbound webhook are the same three-part judgement over different values.
//
// v0 compiles these in as data. They are already shaped as data rather than code so
// that externalizing them into declarative framework models (ADR-004) is a move, not a
// rewrite. Nothing here parses or understands a language.
package model

import (
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

// --- how values acquire a class ------------------------------------------

// Seeding strategies. Which one a rule uses is explicit rather than implied, so a new
// kind of origin is a data change. The set of strategies is the remaining code
// surface, and shrinking it is the standing generalization work.
const (
	// MatchEntryParamProperty: a property access on a parameter of an entry point,
	// e.g. req.query.host.
	MatchEntryParamProperty = "entry-param-property"
	// MatchValueKind: any value the frontend lowered with a given kind, e.g. the
	// binding of a catch clause.
	MatchValueKind = "value-kind"
	// MatchCallResult: the result of calling a known symbol.
	MatchCallResult = "call-result"
	// MatchCallMethodResult names a result by the receiver method rather than the resolved
	// callee symbol. Framework helper objects are often passed under application-chosen
	// names, while their API method remains stable.
	MatchCallMethodResult = "call-method-result"
	// MatchGlobalProperty: a property access on a framework-bound global, e.g.
	// Flask's `request`. Added because a request object is not always a handler
	// parameter — the judgement is identical, the plumbing is not.
	MatchGlobalProperty = "global-property"
	// MatchEntryCallProperty: a property read off the RESULT of a call the handler
	// made with its own request — `const { auth } = await parseRequest(request)`.
	//
	// A fourth plumbing for the same judgement (ADR-004). A framework that hands the
	// handler a bare `Request` gives it no place to hang an identity, so applications
	// built on one parse and authenticate in a helper and destructure the answer. The
	// call is the application's own, so the rule cannot name it; what it names is the
	// SHAPE — a property of a result, in a handler, off a call that was handed the
	// handler's request.
	MatchEntryCallProperty = "entry-call-property"
	// MatchStoreRead: the result of a read from a store that some entry point writes
	// data of another class into.
	//
	// The only seeding strategy whose evidence is a PAIR of call sites in different
	// requests rather than one expression. It is the deliberate opposite of every rule
	// above it: those say where a value entered THIS request, and this one says a value
	// entered an EARLIER one and came back.
	MatchStoreRead = "store-read"
	// MatchFunctionParamProperty: a parameter, or one of its properties, handed to a
	// named lifecycle hook. Both measured argv flows cross framework dispatch the call
	// graph cannot resolve: a SearxNG engine's search(query, params), and JupyterHub's
	// add_system_user(user). The hook contract is the trust boundary in those cases.
	MatchFunctionParamProperty = "function-param-property"
	// MatchRoutePathParam: a handler parameter the ROUTE this handler is registered at
	// declares. `@app.route("/run/<cmd>") def run(cmd)` and Django's
	// `re_path(r"^opencode/(?P<path>.*)$", proxy)` both bind a URL capture straight to
	// the handler's own parameter, and no rule above can say that: every other strategy
	// names a PROPERTY of something, and here the parameter IS the value.
	//
	// The route is what makes it exact rather than a guess about positions. A parameter
	// is caller data when the path this handler is registered at declares a parameter of
	// that name -- so `self`, the request object, and the `form` a lifecycle hook is
	// handed are all untouched, with no list of names to maintain.
	MatchRoutePathParam = "route-path-param"
	// MatchProperty classifies a property by what the property itself is named, without
	// claiming anything about the object it was read from. Used only for values whose
	// role is stated by the leaf -- a stored token or signature compared with caller
	// input -- and never as a general secret-name heuristic.
	MatchProperty = "property"
)

// SourceRule locates values of a class by their origin.
type SourceRule struct {
	Match string // one of the Match* constants

	// MatchEntryParamProperty
	Framework  string
	EntryKind  string
	ParamIndex int
	Paths      []string

	// LeafContains matches on the LAST segment of the access path, which is where a
	// request says what a field IS. `body.password` and `body.user.credentials.apiKey`
	// both name a secret and share no prefix; the leaf is the only part that carries the
	// meaning.
	//
	// A name list, and used in the narrowest way this project allows: it decides a
	// CLASSIFICATION over request paths, not over local variable names. That distinction
	// is why it works here and why a matching attempt over variable names did not --
	// every credential-shaped local in the clean corpus turned out to be a counter of
	// language-model tokens.
	LeafContains []string
	// LeafExcept vetoes, checked first. A CSRF token is a credential nobody hides: the
	// page has to read it back and echo it.
	LeafExcept []string

	// LeafEquals matches the last path segment EXACTLY, ignoring case and separators, so
	// `is_admin`, `isAdmin` and `ISADMIN` are one entry.
	//
	// Containment is right for credentials -- `access_token` and `refreshToken` both name
	// secrets -- and wrong for privileges. wikijs has a setup form with an `adminEmail`
	// field, and a rule that took "contains admin" as a claim of authority read an
	// auto-increment id check as a security decision.
	LeafEquals []string

	// ExactPath seeds only the path itself and not anything read out of it.
	//
	// `request.args` and `request.args.name` are both caller-supplied, so the usual
	// prefix match is right there. `process.env` and `process.env.AWS_REGION` are not
	// the same thing at all: one is every secret the process holds and the other is a
	// value the application chose to publish, and treating the second as the first
	// reports every application that puts its region in a health check.
	ExactPath bool

	// MatchValueKind
	ValueKind string

	// Trust is who supplies the values this rule seeds, when that is not a remote
	// caller. Empty means remote, which is what every source was before there was
	// anything but a request.
	//
	// It exists so that surface completeness keeps asking its own question. That count
	// reads "code that handles caller input and that no entry point reaches" as evidence
	// a ROUTE was missed -- and a management command's argument is untrusted in exactly
	// the way a request field is while being no evidence of that at all.
	Trust ir.Trust

	// MatchCallResult
	Symbol string
	// Method is the receiver-method spelling of a MatchCallMethodResult source. Tornado's
	// get_argument is the case: the helper receives a handler under an application-chosen
	// parameter name, so the symbol is not stable and the API method is.
	Method string

	// SymbolLeaf matches the symbol's LAST dotted segment instead of the whole of it,
	// for a name distinctive enough that whatever it hangs off does not change what it
	// does. `urlopen` is the whole of the list this was added for: the stdlib spells it
	// `urllib.request.urlopen` and applications spell it `self.ydl.urlopen`,
	// `ydl.urlopen` and `self._downloader.urlopen`, and every one of them opens a URL.
	//
	// Deliberately opt-in per rule rather than a general fallback. Most of the names in
	// this model are ordinary words -- `get`, `post`, `request` -- whose meaning is
	// entirely in what they hang off, and matching those by leaf would classify every
	// dictionary lookup in the program.
	SymbolLeaf bool

	// ArgBelow narrows a call-result source to calls that were WRITTEN with a number
	// smaller than this in a particular argument.
	//
	// How many random bytes are enough cannot be answered at the call -- measured across
	// the clean corpus, every short one was a unique suffix, a parameter name, a colour,
	// a temporary table, or a slug checked for collisions in a loop, and none of them
	// were secrets. The length only becomes a defect once the value reaches somewhere
	// unguessability is the point, so the length is recorded HERE and judged there.
	ArgBelow      *int
	ArgBelowIndex int

	// ArgOneOf narrows a call-result source to calls WRITTEN with one of these strings
	// in argument zero, compared without regard to case.
	//
	// Which algorithm a digest is comes from the same place the length of a random value
	// does: it is written in the call, and a library that takes the algorithm as a string
	// is the only one where reading it is possible at all. `createHash("md5")` and
	// `createHash(algorithm)` are the same symbol and only the first says anything -- an
	// algorithm chosen at runtime is not matched and is not guessed at, which is the line
	// every literal-reading rule in this model draws.
	//
	// This exists because the class of a value can depend on a literal at its origin, and
	// before it did, a classification could only be all-or-nothing about a symbol. The
	// alternative was one classification per algorithm name, which is a list of rules
	// where the model already has a list of strings.
	ArgOneOf []string

	// MatchStoreRead
	//
	// WrittenClass is the classification that must have been WRITTEN into the store for
	// a read out of it to carry this one. It is the whole of what keeps second-order
	// taint from being universal: a store nobody puts caller data into answers with
	// nothing a caller wrote, however many times it is read.
	WrittenClass string
	// Medium narrows the rule to one kind of store, so that the noise of each can be
	// measured -- and withdrawn -- separately.
	Medium string

	// MatchFunctionParamProperty
	Function string
}

// Classification assigns a data class to values by where they come from. What makes a
// value sensitive is a property of its origin, not of the defect it later causes.
type Classification struct {
	Class string // "untrusted-input" | "internal-error" | "credential" | ...
	Label string // human phrasing, for evidence
	Rules []SourceRule
}

// --- where values can go --------------------------------------------------

// Channel is a place a value can go: an operation that interprets it, or a medium
// that exposes it. Described by properties — who observes it, and what syntax it
// interprets — never by the defect it enables.
type Channel struct {
	ID string

	// Visibility is who can observe what reaches this channel.
	//   public     — anyone who can reach the application
	//   operator   — people with access to logs and internal systems
	//   thirdparty — a system outside this trust boundary
	//   internal   — stays inside the application
	Visibility string

	// Context is the syntax this channel interprets its input as, if any. A transform
	// only neutralizes a value for the context it actually addresses.
	Context string

	// Matching. ReceiverIsEntryParam narrows a method-name match to a receiver that
	// traces back to a specific entry-point parameter, which is what keeps
	// `res.json(...)` from matching every `.json()` in the program.
	Symbol               string
	Method               string
	ReceiverIsEntryParam int
	ArgIndex             []int
	// RequiredKeyword maps keyword spellings to the ArgIndex they bind for this
	// external API. A named argument still cannot answer a positional question in the
	// IR: this exception exists only because the channel's external symbol supplies
	// the missing signature fact.
	RequiredKeyword map[string]int

	// RequiresExternalReceiver marks a channel that describes an operation on
	// something OUTSIDE this process — a store whose records outlive the request and
	// are shared between callers.
	//
	// `delete` and `update` name a database operation and a Map operation equally
	// well. Matching on the method name alone made every `Set.delete(id)` and
	// `heartbeatTimers.delete(id)` a record selector, and asking who owns an entry in
	// a process-local map is not a question that has an answer. The frontend states
	// what the receiver is in its language; this says the channel needs that answer to
	// be something more than one of the language's own containers.
	//
	// A frontend that cannot type its receivers leaves this unanswerable, and an
	// unanswered question does not satisfy the requirement — it costs confidence
	// instead (ADR-005), because a match this weak has not earned a gate. NO TYPE AT
	// ALL is what "unanswerable" means here: a type that is simply not a builtin is an
	// answer, and a perfectly ordinary one for an ORM.
	RequiresExternalReceiver bool

	// PatternArg names where the regular expression this call uses is WRITTEN: -1 for the
	// receiver, or an argument index. The channel then matches only when that pattern is
	// one that can be made to backtrack exponentially (see CatastrophicPattern).
	//
	// This is the other direction of the regex weakness, and the common one. The engine
	// already reports a caller who writes the PATTERN, which is rare; a caller who feeds
	// a bad pattern is how ReDoS actually happens, and `if (!EMAIL.test(req.body.mail))`
	// is where it lives. Both halves are decidable and neither is decidable alone: a
	// nested quantifier is only a problem if something long and hostile reaches it, and
	// an untrusted string is only a problem if the pattern can be made to churn on it.
	PatternArg *int

	// AllowsComposedPrefix readmits a COMPOSED value when the caller's part comes FIRST.
	//
	// RequiresWholeValue exists so that `fetch("https://api.example.com/" + id)` is not
	// reported: the caller supplies a path segment and the host is the program's. But
	// `needle.get(req.query.url + req.query.symbol)` is composed too, and there the caller
	// supplies the host -- nodegoat's server-side request forgery is written exactly that
	// way, and the whole-value rule silenced it.
	//
	// Position is what separates them, and nothing else does. Asking instead whether any
	// literal piece contains a scheme was tried and measured: it readmitted nodegoat and
	// two coincidences with it, because a program that keeps its base URL in a constant
	// writes no scheme at the call either. What is first, though, is first -- if nothing
	// precedes the caller's value then the program named no destination at all.
	AllowsComposedPrefix bool

	// ComposedContains requires a WORD to appear in one of the literal pieces the sink
	// value was built from.
	//
	// A method name is not a library. `query`, `execute`, `one` and `many` are ordinary
	// English, and a program that composes `${user}@${domain}` and hands it to something
	// called `query` is doing a WebFinger lookup, not SQL -- nodebb does exactly that, and
	// it read as an injection the moment call resolution improved enough to see it.
	//
	// What tells a statement from a string is that a statement says what it does. Every
	// real SQL injection has SELECT, INSERT, UPDATE or DELETE written in one of its
	// literal pieces, because the attacker only supplies the operand; the program still
	// has to say the verb. Asking for the verb costs nothing a real finding has and
	// removes a whole family of coincidences.
	ComposedContains []string

	// Language restricts a channel to one frontend, for the rare rule that is about a
	// method only one language has.
	//
	// `"...".format(x)` is Python's, and a caller who writes the format string chooses the
	// conversions -- which is CWE-134. JavaScript has no such method and plenty of objects
	// with a `format` of their own: `dayjs(when).format("HH:mm")` matched this channel
	// exactly, receiver and all, and reported a date formatter as a format-string attack.
	//
	// Used sparingly and never as a substitute for a discriminator. A rule that is really
	// about a shape should say what the shape is; this is for the case where the method
	// genuinely does not exist in the other language.
	Language string

	// ReceiverFrom narrows a method-name channel by WHAT MADE THE RECEIVER.
	//
	// `update` is a method name with no identity of its own -- a hash, a stream, an ORM
	// record and a Map all have one. What makes a particular `update` a digest is that
	// the object it is called on came out of `crypto.createHash`, and that is a question
	// about the program's structure rather than about a name: the frontend already
	// records which call produced which value, so the answer is a lookup.
	//
	// Written as final segments (`createHash`), matched against the producing call's
	// symbol, and followed back through plain assignments so that the chained form and
	// the two-statement form are the same channel. A receiver whose producer cannot be
	// found is not a match, which keeps the silence honest (ADR-003): the channel says
	// what it needs, and an unanswered question is not a yes.
	ReceiverFrom []string

	// ReceiverNotFrom excludes a method-name channel when WHAT MADE THE RECEIVER
	// proves that the shared name has a different meaning.
	//
	// Node's Hash, Hmac, Cipheriv and Decipheriv all expose `update`, and umami had
	// two CWE-639 findings because that name was read as an ORM operation even with
	// the Node types installed. The constructor is the identity available in both
	// typed and untyped IR. An unknown producer remains a match: absence of proof
	// that this is crypto must not remove real ORM updates across the corpus.
	ReceiverNotFrom []string

	// RequiresUntrustedReceiver marks a channel whose identity comes from WHAT IT IS
	// CALLED ON rather than from its name.
	//
	// `save` is the most overloaded method name in either language. Every ORM record,
	// every document, every settings object has one, and matching the name alone would
	// repeat the `.execute` flood exactly. What distinguishes storing an upload is that
	// the receiver is itself caller-supplied: `request.files["f"].save(dest)` is called on
	// data that arrived in the request, and `user.save()` never is.
	//
	// This asks the dataflow a question it has already answered. The receiver is a
	// tracked value, so "did untrusted data flow into the thing this was called on" costs
	// a map lookup and is far stronger evidence than any name.
	RequiresUntrustedReceiver bool

	// RequiresUnprojectedReceiver narrows that further: the receiver must be the
	// classified value ITSELF rather than a field read out of something the
	// classification reached.
	//
	// `request.files["f"].save(dest)` is called on the upload. A service object that a
	// shared helper returned, in a program where some other route once handed that helper
	// caller data, is not an upload however tainted it looks -- and n8n's snapshot store
	// is exactly that.
	RequiresUnprojectedReceiver bool

	// Qualifiers are conditions on the call's own literals that must hold for this to be
	// a dangerous destination at all.
	//
	// An XML parser is the clear case. libxmljs resolves external entities only when
	// asked -- `parseXmlString(data, {noent: true})` -- and the same call without that
	// option is the safe way to parse XML. The destination is not dangerous by identity;
	// it is dangerous by configuration, and the configuration is written right there in
	// the call.
	Qualifiers []ArgCondition

	// TargetArg names the argument holding the thing being WRITTEN TO, for a channel
	// that has one. A fresh object literal there is a clone and not a record.
	//
	// `Object.assign({}, req.body)` copies the caller's data into a new object nobody
	// has read yet, which is how four files in one production repository make a mutable
	// copy of a request. `Object.assign(user, req.body)` writes it onto a record that
	// already exists and already has fields the caller should not reach. Same symbol,
	// same argument, opposite meanings, and the difference is one argument to the left.
	TargetArg *int

	// RequiresArgs is the number of arguments the call must actually have.
	//
	// A caller-supplied format string with nothing to format is harmless: the whole
	// weakness is that a format walks the objects it is HANDED, and `template.format()`
	// is handed none. It also does the work of a type the Python frontend cannot supply
	// -- superset builds a SQLScript and calls its own `.format()` with no arguments,
	// which is the same method name on a receiver the caller influenced and is not a
	// format string at all.
	RequiresArgs int

	// MaxArgs is the number of arguments the call must NOT exceed, for a destination
	// that is only dangerous in its DEFAULT configuration.
	//
	// lxml's `fromstring(data)` uses a parser that resolves entities; `fromstring(data,
	// parser)` uses the one the application built, and building one is how the weakness
	// is fixed. Reporting both makes the rule report its own remedy, which is how the
	// argument-injection rule was withdrawn. The engine cannot see how that parser was
	// configured, so the honest line is silence on the form that supplies one.
	MaxArgs int

	// RequiresUnenclosed marks a channel where the danger is handing over the caller's
	// object WHOLE.
	//
	// `user.update(req.body)` writes every field the caller sent, including the ones
	// nobody meant to expose -- a role, an id, a balance. `user.update({ name:
	// req.body.name })` writes one field the application named, and is the correct way
	// to do it. The two are indistinguishable by symbol and by argument index, and are
	// told apart by whether the value became a PART of something on its way here.
	//
	// The frontends record that as a distinct flow kind, so this asks about structure
	// rather than about text: composition is the same question for strings, and this is
	// it for objects.
	RequiresUnenclosed bool

	// RequiresEnclosure is the inverse structural question: the destination interprets
	// each member of a collection independently, so the caller's value must have become
	// an ELEMENT on its way there. An argv vector is the measured case. Requiring the
	// enclosure keeps the shell channel unchanged and keeps a composed command string
	// from being reported a second time as argument injection.
	RequiresEnclosure bool

	// RequiresComposition marks a channel that interprets a STATEMENT its caller built.
	// The untrusted value must have been concatenated or interpolated into text on its
	// way here; a value passed along whole is data being handed over, not a program
	// being written.
	RequiresComposition bool

	// RequiresWholeValue is the mirror image, and the pair is not a coincidence: what a
	// destination interprets decides which one it needs.
	//
	// A SQL statement is BUILT, so untrusted data composed into it is the defect. A
	// request destination is CHOSEN, so untrusted data composed into it usually is not:
	// `axios.get(BASE + "/users/" + id)` fixes the host in the literal and leaves the
	// caller only a path segment, which cannot move the request to another machine.
	//
	// The cost is a stated false negative. `"https://" + host` IS caller-chosen and is
	// composed, so it is missed. That shape is rarer than a fixed base with a variable
	// path, and a miss is the cheaper error here: the alternative floods every service
	// that builds a URL from an id, which is most of them.
	RequiresWholeValue bool

	// CWE identifies the weakness when reaching THIS channel determines it. One
	// policy can govern several channels whose weaknesses differ: untrusted input
	// choosing what a shell runs is CWE-78, and choosing which executable runs is
	// CWE-73. The judgement is the same; the identity is not.
	CWE string

	Rationale string
}

// --- what is forbidden ----------------------------------------------------

// Policy forbids a pairing. This is where a defect is defined: as a judgement about
// classes and channels, not as a shape of code. Because a policy denies by channel
// PROPERTY, it applies to channels that do not exist yet.
type Policy struct {
	ID    string
	Class string

	DeniedVisibility []string
	DeniedContext    []string

	// ClassNamesTheWeakness makes this policy's CWE win over the channel's.
	//
	// Normally the channel names the weakness, and that is right for a broad policy
	// refined by where it lands: untrusted input reaching an interpreter is CWE-89 at a
	// database, CWE-79 in markup, CWE-78 at a shell. One rule, many identities, and the
	// destination is what decides.
	//
	// It is exactly wrong for a policy whose CLASS decides. Internal failure detail
	// leaving the system is CWE-209 whether the page escaped it or not -- and before this
	// flag existed the same policy reported CWE-209 on an escaped template slot and
	// CWE-79 on an unescaped one, purely because the second channel happened to name a
	// number. The finding said "sensitive information exposure" and carried the identity
	// of cross-site scripting.
	ClassNamesTheWeakness bool

	// RequiresComposition is an ADDITIONAL requirement this judgement makes, on top of
	// whatever the channel asks.
	//
	// A channel states what its destination interprets, which is right while one policy
	// uses it and insufficient the moment two do. Both rules that write to a log want the
	// same destination and disagree about this: a credential is a disclosure whether it
	// was logged whole or built into a sentence, and forging a log LINE requires the
	// caller's text to have been built into one. Putting it on the channel silenced the
	// first rule in order to enable the second.
	RequiresComposition bool

	// RequiresUnprojected forbids the pairing only for the WHOLE structure, not for
	// something read out of it.
	//
	// `res.json(process.env)` hands over every secret the process was started with.
	// `res.json({region: process.env.AWS_REGION})` hands over one value the application
	// chose to publish, and applications publish configuration on purpose all the time.
	// The difference is a property read, which the IR already records as its own flow
	// kind -- so this is the third structural question after composition and enclosure,
	// and it needed no new fact to ask.
	RequiresUnprojected bool

	// RequiresRelationTo permits the pairing only when the handler relates the value
	// to data of another class — the difference between "this must never happen" and
	// "this is only safe when it was checked". Selecting a record by a caller-supplied
	// identifier is fine; doing it without ever consulting who the caller is, is not.
	RequiresRelationTo string
	RequiredContext    []string

	// Requires are the capabilities this policy needs. A policy that cannot be
	// evaluated is reported as unevaluated, never as satisfied (ADR-003).
	Requires Requirements

	// ExemptedBy names a declared application property that makes this judgement
	// inapplicable. Naming the property here keeps the exemption general: the engine
	// never learns what "registration" is, only that a policy can be exempted.
	ExemptedBy string

	// AudienceDecides marks a judgement whose weight IS who receives what is disclosed.
	//
	// For almost every rule here the audience is beside the point: an injection behind a
	// login is the same injection, because the attacker's power over the system does not
	// change with who they are. A DISCLOSURE is the exception -- the whole weakness is
	// that somebody learned something, so who that somebody is decides how much it
	// matters. An internal error returned to a stranger describes the system to whoever
	// asked; the same string returned to a caller who already holds an account describes
	// it to somebody who is already inside.
	//
	// Marked on the policy rather than read off a CWE in the reporter, because the
	// reporter does not decide what is true. It changes rank only: the finding is
	// reported either way, and nothing about it stops gating that did not already.
	AudienceDecides bool

	Reason  string // the judgement, stated plainly, for the finding
	Finding string // finding class
	CWE     string
}

// Applies reports whether this policy governs a class reaching a channel.
func (p Policy) Applies(class string, ch Channel) bool {
	if p.Class != class {
		return false
	}
	for _, c := range p.RequiredContext {
		if c == ch.Context {
			return true
		}
	}
	for _, v := range p.DeniedVisibility {
		if v == ch.Visibility {
			return true
		}
	}
	for _, c := range p.DeniedContext {
		if c == ch.Context {
			return true
		}
	}
	return false
}

// --- transforms -----------------------------------------------------------

// SanitizerRule declares which contexts a function actually neutralizes. A transform
// whose contexts do not include the channel's context is recorded in the evidence as
// considered-and-insufficient rather than silently ignored (ADR-006).
type SanitizerRule struct {
	Symbol   string
	Contexts []string
	Note     string

	// RequiresLiteralArg names an argument that must have been written as a literal for
	// this rule to apply, or nil when it always applies.
	//
	// `url_for("auth.login", next=request.full_path)` builds a URL whose host and path
	// come from a named endpoint, and puts the caller's data in the query string. The
	// destination is fixed by the literal and the caller cannot move it -- but only
	// while the endpoint IS a literal. `url_for(whatever_the_caller_said)` is the
	// weakness this rule would otherwise hide, so the condition is part of the rule
	// rather than a footnote to it.
	RequiresLiteralArg *int

	// RequiresInputArg limits a transform to data arriving through one argument. This
	// is different from requiring a literal: `url_concat(base, query)` percent-encodes
	// the query mapping, but does not make an attacker-controlled base safe. Recording
	// which argument carried the classified value keeps those two paths distinct.
	RequiresInputArg *int

	// Method matches the FINAL SEGMENT of a traversed symbol, for a transform whose name
	// is a method rather than something imported. AfterSymbol requires that the same
	// expression was built on one of these calls.
	//
	// Node splits a digest across three calls -- `createHash(alg).update(data).digest()`
	// -- so the thing that ends the password is a method on an object, and the only
	// evidence of WHICH object is the chain the frontend already rendered. `digest`
	// alone would be a name with no identity; `digest` on something that came out of
	// `createHash` is a digest.
	Method      string
	AfterSymbol []string

	// Except names classifications this transform does NOT end, checked before Classes.
	//
	// A transform cannot clear the class it CREATES. `createHash("md5").digest()` ends
	// "this is a password" and "this is caller input" -- a digest is not what was
	// digested -- and in the same call it begins "this is a digest from a broken
	// algorithm". Without this the weak-digest class was sanitized by the very call that
	// produced it, and every judgement about where the digest went went quiet.
	//
	// Stated as an exception rather than by listing the classes the transform does clear,
	// because the list would be wrong at the next classification somebody adds and would
	// be wrong SILENTLY: a one-way transform genuinely does end everything else.
	Except []string

	// Classes narrows a transform to the classifications it actually ends. Empty means
	// every one.
	//
	// Signing is the case that needed it. A signed token is unguessable however
	// guessable the payload was, so signing ends "this came from the clock" -- and it
	// does not end "there is a password in here", because a JWT payload is base64 and
	// not a secret. One transform, two different answers, and the difference is WHICH
	// classification is asking.
	Classes []string
}

// AppliesTo reports whether this transform speaks to a classification at all.
func (s SanitizerRule) AppliesTo(class string) bool {
	for _, c := range s.Except {
		if c == class {
			return false
		}
	}
	if len(s.Classes) == 0 {
		return true
	}
	for _, c := range s.Classes {
		if c == class {
			return true
		}
	}
	return false
}

// arg is a pointer to an argument index, for the optional condition above.
func arg(i int) *int { return &i }

// atLeast is a pointer to a threshold, for a shape that matches values below it.
func atLeast(i int) *int { return &i }

// atMost is a pointer to a threshold, for a shape that matches values above it.
func atMost(i int) *int { return &i }

// Clears reports whether this transform neutralizes a value for a channel context.
func (s SanitizerRule) Clears(context string) bool {
	for _, c := range s.Contexts {
		// A ONE-WAY transform is not context-specific. Escaping answers a question about
		// where a value is going, and every sanitizer here but these does exactly that.
		// A password hash is not a password anywhere: not in a log, not in a response,
		// not in a query. Saying so once beats listing every context it is safe in and
		// then being wrong about the one that gets added next.
		if c == AnyContext || c == context {
			return true
		}
	}
	return false
}

// lastKeySegment reads an option key on its last segment. An option written inside a
// named group is the same option: `cookie.maxAge` and `maxAge` are one decision, and the
// group it sits in is not what makes it one.
func lastKeySegment(key string) string {
	key = strings.ToLower(key)
	if i := strings.LastIndex(key, "."); i >= 0 {
		return key[i+1:]
	}
	return key
}

// AnyContext marks a transform whose output is not the thing that went in, whatever it
// is about to be used for.
const AnyContext = "*"

// CallbackRule propagates a class ACROSS a higher-order call, in one of two directions.
// This is what carries data across the callback and promise boundaries that most of Node
// is built out of.
//
// Inward is the original and the common one: the class on a method's RECEIVER reaches a
// parameter of the function handed to it (`arr.forEach(x => ...)`, `p.then(v => ...)`).
//
// Outward is the mirror image, and a value that takes it is invisible without it. One of
// the callback's own parameters is a CONTINUATION rather than a value, and whatever is
// handed to that continuation is what the call itself answers with.
// `new Promise(resolve => ...)` is the whole of the shape: the executor returns nothing,
// and everything the promise ever carries was passed to `resolve` -- routinely from
// several callbacks deep inside the executor, which is where the value actually is.
type CallbackRule struct {
	// Method matches a method call by name. Symbol matches by the symbol the frontend
	// resolved the callee to, which is what a CONSTRUCTOR has instead: `new Promise(...)`
	// is called on nothing, so there is no method name and no receiver.
	Method      string
	Symbol      string
	CallbackArg int
	// CallbackParam is the callback parameter the receiver's class flows INTO. Only
	// meaningful for a rule matched on a Method, because a call with no receiver has
	// nothing to carry inward.
	CallbackParam int
	// ResolverParam names a callback parameter that is a CONTINUATION, and turns the rule
	// around: a value handed to that parameter flows OUT, to the result of the call the
	// callback was passed to. Absent for every ordinary callback, where the parameters
	// are values and the return is the answer.
	ResolverParam *int
	// ResolverArg is which argument OF the continuation carries the value. Zero for every
	// promise: `resolve(value)`.
	ResolverArg int
	Note        string
}

// argIndex names an argument position in a rule that may also leave it unnamed.
func argIndex(i int) *int { return &i }

// ControlRule classifies a named function as a security control. It is only a
// CLASSIFIER, never the detector of record: convention analysis treats any shared
// middleware binding as a signal whether or not it appears here (ADR-010).
type ControlRule struct {
	Name string
	Kind string // "authentication" | "authorization" | "rate-limit"
}

// --- capabilities ---------------------------------------------------------

// Requirements are the frontend capabilities an analysis needs. Unmet requirements
// make the analysis NOT APPLICABLE — never a clean result (ADR-003).
type Requirements struct {
	TypeChecker     bool
	Interprocedural bool
	ControlFlow     bool
	// FrameworkModels are the framework idioms this rule reads facts from. A rule whose
	// whole subject is a declaration only one framework makes cannot be evaluated where
	// the frontend never looked for it, and reporting that as a clean result is the
	// failure ADR-003 exists to prevent: a Python frontend that models Django URLconfs
	// and does not model DRF view classes is not silent about DRF because DRF is
	// correct.
	FrameworkModels []string
}

// Missing reports which required capabilities the frontend does not declare.
func (r Requirements) Missing(c ir.Capabilities) []string {
	var missing []string
	if r.TypeChecker && !c.TypeChecker {
		missing = append(missing, "typeChecker")
	}
	if r.Interprocedural && !c.Interprocedural {
		missing = append(missing, "interprocedural")
	}
	if r.ControlFlow && !c.ControlFlow {
		missing = append(missing, "controlFlow")
	}
	for _, want := range r.FrameworkModels {
		if !slices.Contains(c.FrameworkModels, want) {
			missing = append(missing, "frameworkModels="+want)
		}
	}
	return missing
}

// --- model ----------------------------------------------------------------

type Model struct {
	Classifications []Classification
	Channels        []Channel
	CallShapes      []CallShape
	Decisions       []DecisionRule
	Stores          []StoreRule
	// Persistence is where values are PUT and where they come BACK -- a store, modelled
	// as a place rather than as a call that happens to be traversed.
	Persistence []StoreAccess
	Policies    []Policy
	Sanitizers  []SanitizerRule
	// Resolvers are calls that re-parse a value as a URL REFERENCE. They are neither
	// sanitizers nor channels: they change what a composition MEANS, which is a fact
	// about the value rather than about where it is going.
	Resolvers  []ResolverRule
	Callbacks  []CallbackRule
	Controls   []ControlRule
	Literals   []LiteralRule
	ClientRole ClientRoleRule
	Guards     []GuardRule
	Scopes     []ScopeRule
	// ArgvNoOptionPrograms is deliberately an allowlist rather than a presumption. Most
	// command-line programs accept options, and an unknown executable therefore proves
	// nothing about whether a dash-leading argument changes its operation.
	ArgvNoOptionPrograms []string
	TaintFlowReq         Requirements
	SurfaceReq           Requirements
}

// ChannelsMatching returns channels a call site could be. Receiver narrowing is
// applied by the engine, the only thing that knows what a receiver resolves to.
func (m Model) ChannelsMatching(symbol, method string) []Channel {
	var out []Channel
	for _, c := range m.Channels {
		if c.Symbol != "" && c.Symbol == symbol {
			out = append(out, c)
			continue
		}
		if c.Method != "" && c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

// PoliciesFor returns every policy violated by a class reaching a channel.
func (m Model) PoliciesFor(class string, ch Channel) []Policy {
	var out []Policy
	for _, p := range m.Policies {
		if p.Applies(class, ch) {
			out = append(out, p)
		}
	}
	return out
}

// SanitizerFor returns the transform rule for a resolved external symbol, if any.
// IdentityClass names the classification that represents the caller's identity. Kept as
// a method rather than a literal so that the report and the engine cannot drift apart on
// what the word means.
func (m Model) IdentityClass() string { return "actor-identity" }

// UntrustedClass names the classification for data a caller supplied.
func (m Model) UntrustedClass() string { return "untrusted-input" }

// CallerCredentialClass names the classification for a field the caller sent that IS a
// secret rather than ordinary request data.
func (m Model) CallerCredentialClass() string { return "caller-credential" }

// NamesSecretField reports whether a request field's own name says the value in it is a
// SECRET the caller had to possess, rather than an identifier the caller could have
// guessed.
//
// The vocabulary is read out of the caller-credential classification rather than written
// again here, so there is one list: the same words that make `body.password` a credential
// make `input.token` one, and a codebase that teaches the model a new spelling teaches
// every rule that asks this question at once. The CSRF veto comes along with it for the
// reason it was written -- a page has to echo that token back, so it is a credential
// nobody hides.
//
// The identifier suffix is this question's own addition, and it is the whole difference
// between the two weaknesses that share this shape. Selecting a record by a value the
// caller sent is authentication when the value is a secret and an IDOR when it is a row
// id, and `tokenId`, `apiKeyId` and `secretId` are row ids wearing a credential word:
// they name the row a secret is stored IN, which is exactly as enumerable as any other
// primary key. Excluding them costs the shapes that end in an id and are secrets anyway
// -- a session id in a cookie is one -- and the direction of that loss is the safe one,
// because a name this declines to call a secret is a route the engine keeps reporting.
func (m Model) NamesSecretField(leaf string) bool {
	leaf = NormalizeFieldName(leaf)
	if leaf == "" {
		return false
	}
	if strings.HasSuffix(leaf, "id") || strings.HasSuffix(leaf, "ids") {
		return false
	}
	var names, except []string
	for _, c := range m.Classifications {
		if c.Class != m.CallerCredentialClass() {
			continue
		}
		for _, r := range c.Rules {
			names = append(names, r.LeafContains...)
			except = append(except, r.LeafExcept...)
		}
	}
	for _, e := range except {
		if strings.Contains(leaf, NormalizeFieldName(e)) {
			return false
		}
	}
	for _, n := range names {
		if strings.Contains(leaf, NormalizeFieldName(n)) {
			return true
		}
	}
	return false
}

// ArgvProgramHasNoOptions reports the exceptional programs whose argument grammar has
// no option surface. The shipped list is empty until a command earns that claim by
// documented semantics; callers can extend the declarative model without weakening the
// default for unknown executables.
func (m Model) ArgvProgramHasNoOptions(program string) bool {
	program = strings.TrimSpace(program)
	if i := strings.LastIndexAny(program, `/\\`); i >= 0 {
		program = program[i+1:]
	}
	for _, allowed := range m.ArgvNoOptionPrograms {
		if program == allowed {
			return true
		}
	}
	return false
}

// ResolverRule names a call that resolves a RELATIVE REFERENCE against a base URL, and
// which argument carries the reference.
//
// It exists because a destination channel asks a structural question -- did the caller
// supply the whole address, or only a segment after a fixed prefix -- and this call is
// where that question stops having the obvious answer. `urljoin` re-parses what it is
// handed, and RFC 3986 says a reference beginning `//` is a NETWORK-PATH REFERENCE whose
// authority replaces the base's. So the literal `/` an application writes in front of
// caller data does not fix the host the way a literal `https://api.example.com/` does:
// the caller supplies the second slash and chooses the machine.
//
// Nothing here is a claim about danger. It is a claim about what a composition MEANT,
// and it applies only where a channel was already asking.
type ResolverRule struct {
	Symbol string
	// RefArg is the argument carrying the reference. The BASE argument is deliberately
	// not listed: caller data in the base is an ordinary whole-value destination and
	// the channel's own rule already reads it correctly.
	RefArg int
	Note   string
}

// ResolvesReference reports whether this symbol re-parses the given argument as a URL
// reference, so that a literal prefix written in front of it no longer anchors a host.
func (m Model) ResolvesReference(symbol string, arg int) bool {
	for _, r := range m.Resolvers {
		if r.Symbol == symbol && r.RefArg == arg {
			return true
		}
	}
	return false
}

// RootRelativeURLPrefix reports whether a written prefix fixes a destination to this
// origin's path space. One slash does; two do not, because `//host` is a network-path
// reference whose authority is `host`. Browsers treat a backslash as a slash while
// parsing special schemes, so `/\host` crosses the same boundary and is not local.
//
// A slash alone proves nothing about the next template span: if that span starts with a
// slash or backslash, the finished value is one of the authority references above. At
// least one statically written path character must follow it. Calls that re-parse a
// separately supplied reference (such as urljoin) remain governed by ResolverRule.
func RootRelativeURLPrefix(prefix string) bool {
	if len(prefix) < 2 || prefix[0] != '/' {
		return false
	}
	return prefix[1] != '/' && prefix[1] != '\\'
}

// AuthorityReferencePrefix is the near-miss to RootRelativeURLPrefix. A destination
// beginning with either spelling can select another authority even though the program
// wrote its first character.
func AuthorityReferencePrefix(prefix string) bool {
	return len(prefix) >= 2 && prefix[0] == '/' && (prefix[1] == '/' || prefix[1] == '\\')
}

func (m Model) SanitizerFor(symbol string) (SanitizerRule, bool) {
	for _, s := range m.Sanitizers {
		if s.Symbol != "" && s.Symbol == symbol {
			return s, true
		}
		if s.Method != "" && s.matchesMethod(symbol) {
			return s, true
		}
	}
	return SanitizerRule{}, false
}

// matchesMethod tests a transform named by a method against a rendered call expression.
func (s SanitizerRule) matchesMethod(symbol string) bool {
	if i := strings.LastIndex(symbol, "."); i < 0 || symbol[i+1:] != s.Method {
		return false
	}
	for _, want := range s.AfterSymbol {
		if strings.Contains(symbol, want+"(") {
			return true
		}
	}
	return len(s.AfterSymbol) == 0
}

// CallbackFor returns the INWARD higher-order propagation rule for a method name, if
// any. A rule with no method name describes a call that has none, and matching it against
// the empty string would make every plain function call a callback site.
func (m Model) CallbackFor(method string) (CallbackRule, bool) {
	if method == "" {
		return CallbackRule{}, false
	}
	for _, c := range m.Callbacks {
		if c.Method == method && c.ResolverParam == nil {
			return c, true
		}
	}
	return CallbackRule{}, false
}

// ResolverFor returns the OUTWARD rule for a call, if this call hands a continuation to a
// function it was given. Symbol and method are both offered because a constructor has
// only the first and a method only the second.
func (m Model) ResolverFor(symbol, method string) (CallbackRule, bool) {
	for _, c := range m.Callbacks {
		if c.ResolverParam == nil {
			continue
		}
		if c.Symbol != "" && (symbol == c.Symbol || lastSegmentOf(symbol) == c.Symbol) {
			return c, true
		}
		if c.Method != "" && c.Method == method {
			return c, true
		}
	}
	return CallbackRule{}, false
}

// lastSegmentOf returns the final dotted segment of a symbol, so that an imported
// `Promise` and a global one are one name.
func lastSegmentOf(symbol string) string {
	if i := strings.LastIndex(symbol, "."); i >= 0 {
		return symbol[i+1:]
	}
	return symbol
}

// Attests reports whether anything in this model has something to say about a call.
//
// It is the question behind "is this hop proven or assumed". When taint crosses a call
// into code that is not in the tree, the engine keeps it -- an unknown callee has no
// known semantics, and over-approximating is the only safe reading of nothing. But a
// model that describes the call is a different situation from a model that does not: an
// escape, a serializer, a store read and a digest are all calls the engine has a
// STATEMENT about, and `badge-maker.makeBadge` is a call it has never heard of and whose
// source it has never seen, where the taint continues on an assumption alone.
//
// Deliberately not a name list and not a package manifest. It asks what this model
// covers, so it stays right as the model grows and needs no lockfile, no registry and no
// guess about which directory a dependency was vendored into.
func (m Model) Attests(symbol, method string) bool {
	if len(m.ChannelsMatching(symbol, method)) > 0 {
		return true
	}
	if _, ok := m.SanitizerFor(symbol); ok {
		return true
	}
	if _, ok := m.CallbackFor(method); ok {
		return true
	}
	if _, ok := m.ResolverFor(symbol, method); ok {
		return true
	}
	if _, ok := m.StoreReadAt(symbol, method, ""); ok {
		return true
	}
	if _, ok := m.StoreWriteAt(symbol, method, ""); ok {
		return true
	}
	if m.ClientRole.IsCarrier(symbol, method) {
		return true
	}
	leaf := lastSegmentOf(symbol)
	for _, c := range m.Classifications {
		for _, r := range c.Rules {
			if r.Match != MatchCallResult {
				continue
			}
			if r.SymbolLeaf && r.Symbol == leaf {
				return true
			}
			if !r.SymbolLeaf && r.Symbol == symbol {
				return true
			}
		}
	}
	for _, sh := range m.CallShapes {
		if sh.Symbol == symbol || (sh.Method != "" && sh.Method == method) {
			return true
		}
	}
	return false
}

// ClassifyControl says what kind of control a name denotes, or "" when it cannot tell.
//
// Matched on the final segment, case-insensitively, and by containment rather than
// equality. Real code writes `authHandler.isAuthenticated`, `JwtAuthGuard` and
// `ThrottlerBehindProxyGuard`; exact equality against a bare name matched none of them, so
// every control on every production repository read as unclassified and the analysis that
// names what is MISSING had nothing to name it with.
//
// The longest rule wins, so `requireAuthorization` is not classified as authentication by
// `requireAuth` happening to be a prefix of it. That ordering is the whole defence against
// containment being too loose, and it is why the rules are sorted rather than ranged over
// in declaration order.
//
// This is still a list of likely names, which is the weakest kind of rule in this project.
// It is supplemented rather than replaced by the population: a control on every entry
// point distinguishes none of them whatever it is called (ADR-010).
func (m Model) ClassifyControl(name string) string {
	if name == "" {
		return ""
	}
	segment := name
	if i := strings.LastIndexByte(segment, '.'); i >= 0 {
		segment = segment[i+1:]
	}
	starts := wordStarts(segment)
	segment = strings.ToLower(segment)

	best, bestLen := "", 0
	for _, c := range m.Controls {
		rule := strings.ToLower(c.Name)
		if len(rule) <= bestLen {
			continue
		}
		for _, i := range starts {
			if strings.HasPrefix(segment[i:], rule) {
				best, bestLen = c.Kind, len(rule)
				break
			}
		}
	}
	return best
}

// wordStarts is where a word begins inside an identifier: at the front, after a
// separator, and at a camelCase hump.
//
// Containment has to begin at one of these or it reads a control into a word that merely
// contains one. `unauthorized` contains `authorize` and is the opposite of a control --
// umami calls it 145 times to WRITE a 401 -- and until control classification could see a
// locally defined call at all, no repository had produced a name where that mattered. The
// first tree it was pointed at produced 136 entry points carrying an "authorization
// control" that answers requests with a refusal.
//
// The cost is the shapes that bury a control word mid-word: `reauthorize`, `deauthorize`.
// Missing a control is a false claim about what is MISSING, which the population analysis
// discounts anyway (ADR-010); inventing one is a false claim about what is THERE, on the
// surface, which is the primary output.
func wordStarts(s string) []int {
	starts := []int{0}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_' || c == '-' || c == '$' || c == '.' || c == '/':
			if i+1 < len(s) {
				starts = append(starts, i+1)
			}
		case c >= 'A' && c <= 'Z' && !(s[i-1] >= 'A' && s[i-1] <= 'Z'):
			starts = append(starts, i)
		case c >= 'a' && c <= 'z' && s[i-1] >= '0' && s[i-1] <= '9':
			starts = append(starts, i)
		}
	}
	return starts
}

// Builtin returns the shipped model.
// Field names that ARE a claim of authority rather than merely mentioning one. Compared
// exactly, ignoring case and separators: containment reads `adminEmail` as a privilege,
// and a setup form is not a security decision.
// Facts about a person that cannot be reissued. Deliberately specific: `passport` alone
// is the authentication library in two of the three places these names appear across the
// clean corpus, and a list that matched it would report a login flow as an identity leak.
// The words a SQL statement has to contain to be one. The caller supplies the operand;
// the program still has to write the verb, so a composed value with none of these in its
// literal pieces is not a statement whatever the method it was handed to is called.
var sqlVerbs = []string{"select ", "insert ", "update ", "delete ", "from ", "where ",
	"union ", "drop ", "alter ", "create ", "truncate ", "values", "join "}

var personalNames = []string{
	"ssn", "socialsecurity", "socialsecuritynumber", "nationalid", "nationalidnumber",
	"passportnumber", "taxid", "taxidnumber", "driverslicense", "driverslicensenumber",
	"dateofbirth", "birthdate", "medicalrecord", "medicalrecordnumber", "diagnosis",
}

var authorityNames = []string{
	"role", "roles", "admin", "isadmin", "isstaff", "issuperuser", "superuser",
	"permission", "permissions", "privilege", "privileges", "scope", "scopes",
	"usertype", "accounttype", "isowner", "ismoderator",
}

// A cookie carrying any of these is being asked to establish who the caller is.
var cookieAuthorityNames = append([]string{"user", "userid", "username", "auth", "authenticated", "loggedin", "isloggedin"}, authorityNames...)

// The algorithms for which producing two inputs with the same digest is a published
// result rather than a research direction. Named where a library takes the algorithm as
// a string; the libraries that name it in the function instead are matched by symbol.
//
// `sha` is Node's spelling of SHA-0, which was withdrawn. `ripemd` is RIPEMD-128,
// which the same attacks reach; RIPEMD-160 is not on this list and is not matched,
// because the comparison is exact.
var weakDigest = []string{"md5", "sha1", "md4", "md2", "ripemd", "sha"}

func Builtin() Model {
	m := builtin()
	// Compiled once, because this kind runs against every literal in the program and a
	// large repository has hundreds of thousands of them. MustCompile is right here: a
	// pattern in the shipped model that does not compile is a build that must not ship.
	for i := range m.Literals {
		if m.Literals[i].Pattern != "" {
			m.Literals[i].re = regexp.MustCompile(m.Literals[i].Pattern)
		}
	}
	return m
}

func builtin() Model {
	return Model{
		// What dataflow actually needs is call resolution, not type inference. The
		// original requirement said typeChecker because the only frontend in
		// existence had one — exactly the over-fitting ADR-008 predicts.
		TaintFlowReq: Requirements{Interprocedural: true},
		// Enumerating the surface needs entry points, which the frontend supplies
		// directly.
		SurfaceReq: Requirements{},

		// WHAT DATA IS. Origin determines class.
		Classifications: []Classification{
			{
				Class: "untrusted-input",
				Label: "data supplied by a caller",
				Rules: []SourceRule{
					{
						Match:      MatchEntryParamProperty,
						Framework:  "express",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths: []string{"query", "body", "params", "headers", "cookies", "files",
							// The request line is caller-supplied too. `req.originalUrl` and
							// `req.hostname` are chosen by whoever made the request -- the
							// latter comes from the Host header -- and code reaches for them
							// constantly when building links back to itself.
							"url", "originalUrl", "path", "hostname"},
					},
					// Fastify hands the handler a request of its own, and it is NOT
					// Express's: `req.originalUrl` and `req.files` do not exist on it, and
					// the four that do -- `query`, `body`, `params`, `headers` -- are the
					// four every Fastify handler reads. One application's 83 routes were
					// labelled express over a Fastify backend, so this rule is what the
					// label now selects.
					//
					// `url` and `hostname` are here because Fastify's request carries both
					// and the Express rule above already treats them as caller-supplied for
					// the reason stated there. Dropping them while correcting the label
					// would have traded a wrong framework for lost coverage on the same
					// handlers.
					{
						Match:      MatchEntryParamProperty,
						Framework:  "fastify",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"query", "body", "params", "headers", "cookies", "url", "hostname"},
					},
					// A route that is a FILE. Next.js App Router, Remix, Nuxt and Medusa
					// all register a handler by putting it at a known path and exporting
					// it, and the frontend enumerates all four -- but nothing here spoke
					// for them, so every one of those routes seeded no source at all.
					//
					// That is worse than not finding the routes, because it does not look
					// like a gap. umami enumerated 168 of 168 entry points, verified file
					// by file by an independent reader, and produced zero dataflow
					// findings from them: the surface was exact and completely inert.
					//
					// The App Router handler takes a Request, so the caller's input is
					// reached through `nextUrl`, `headers`, `cookies` and the body
					// methods. `params` is the second parameter, not a property, and is
					// covered by the route-parameter rule rather than here.
					{
						Match:      MatchEntryParamProperty,
						Framework:  "file-route",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths: []string{"nextUrl", "url", "headers", "cookies", "body",
							"searchParams", "params", "query"},
					},
					// The Pages Router request is Express's request wearing a different
					// type: `req.query`, `req.body`, `req.headers`, `req.cookies`. Same
					// shape, different framework label, because the two conventions live in
					// the same tree and one file cannot be both.
					{
						Match:      MatchEntryParamProperty,
						Framework:  "next-pages",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"query", "body", "headers", "cookies", "url", "socket"},
					},
					{
						// A rendered page is reachable by URL and is not an API route. Next
						// supplies these two props from that URL; keeping the entry kind
						// distinct preserves the API count while giving their values the same
						// provenance they have in a route handler.
						Match:      MatchEntryParamProperty,
						Framework:  "next-app-page",
						EntryKind:  "rendered-page",
						ParamIndex: 0,
						Paths:      []string{"params", "searchParams"},
					},
					{
						// Frameworks that inject request data straight into a
						// handler parameter (NestJS @Param/@Body/@Query).
						Match:     MatchValueKind,
						ValueKind: "untrusted-param",
					},
					{
						// A management command's own arguments, as the argument parser
						// hands them to `handle`.
						//
						// The same CLASS as request data and emphatically not the same
						// TRUST: this is a string a person typed at a shell they already
						// have, so it is the entry point's trust label that ranks the
						// finding rather than this rule. Classified here because what
						// happens next is identical -- a command line interpolated into
						// `os.system` is the same defect whoever typed it.
						Match:     MatchValueKind,
						ValueKind: "operator-param",
						Trust:     ir.Operator,
					},
					{
						Match:  MatchGlobalProperty,
						Symbol: "flask.request",
						Paths: []string{"args", "form", "json", "values", "headers", "cookies", "data", "files",
							// Same reasoning on Flask. A real template injection in the
							// vulnerable corpus interpolates `request.url` into template
							// SOURCE, and was invisible while this list stopped at the body.
							"url", "path", "full_path", "base_url", "url_root", "query_string", "referrer", "user_agent"},
					},
					// The METHOD forms of the same properties, which is how Flask code
					// actually reads a body. `request.get_json()` appears 44 times across
					// the clean corpus and was not a source at all: the property list
					// covered `request.json` and the call was a different shape entirely,
					// so the most common way to read a JSON request in this framework
					// produced values related to nothing.
					{
						// aiohttp hands the request to the handler as a parameter, the
						// way Express does, rather than as a module global the way Flask
						// does. Same judgement, different plumbing (ADR-004).
						Match:      MatchEntryParamProperty,
						Framework:  "aiohttp",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths: []string{"query", "match_info", "rel_url", "headers", "cookies",
							"query_string", "path", "path_qs", "url", "host", "remote", "raw_path"},
					},
					// Django hands the request to the view as a parameter, the way
					// aiohttp does, and names its two form dictionaries after the verbs
					// that carry them: `request.GET` is the query string and
					// `request.POST` is the form body.
					{
						Match:      MatchEntryParamProperty,
						Framework:  "django",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths: []string{"GET", "POST", "FILES", "COOKIES", "META", "body", "headers",
							// The request line, for the reason it is listed for every other
							// framework here: a handler that builds a link back to itself
							// reads the path the caller asked for.
							"path", "path_info", "get_full_path"},
					},
					{
						// The same request, one parameter along. A Django class-based view
						// and a DRF viewset answer in a METHOD, so `self` is the first
						// parameter and the request is the second -- and a rule that only
						// ever looks at the first one is blind to every framework whose
						// handlers are classes, which is most of Django REST Framework.
						Match:      MatchEntryParamProperty,
						Framework:  "django",
						EntryKind:  "http-route",
						ParamIndex: 1,
						Paths: []string{"GET", "POST", "FILES", "COOKIES", "META", "body", "headers",
							"path", "path_info", "get_full_path"},
					},
					// The captures a route declares, wherever the framework puts them --
					// and two of the three Python frameworks here put them in the
					// handler's OWN PARAMETERS, which is a shape none of the rules above
					// can state. aiohttp has `match_info` and Tornado has `path_args`,
					// both properties of something the rules name; Flask and Django have
					// no such object, so `@app.route("/run/<cmd>") def run(cmd)` bound
					// the caller's string to a bare parameter and nothing classified it.
					//
					// Measured: `subprocess.check_output(cmd, shell=True)` one line
					// below that decorator produced no finding at all, and archivebox's
					// `/opencode/<path>` proxy is the same shape one framework along.
					//
					// The ROUTE decides which parameters those are, which is what keeps
					// this from becoming "every parameter of every handler". A path that
					// declares no capture seeds nothing; `self`, the request, and the
					// `form` a Django lifecycle hook receives are never named by a path
					// and are never touched. The stated cost is Django's POSITIONAL
					// groups -- `r"^(\d+)/$"` passes an unnamed capture by position, and
					// a route that gives it no name gives this rule nothing to match.
					{Match: MatchRoutePathParam, EntryKind: "http-route"},
					// Tornado hangs the request off the HANDLER rather than passing it in.
					// A verb method's first parameter is `self` and the caller's data is
					// one hop further along, at `self.request` -- so the judgement is the
					// same one every framework above makes and only the plumbing differs
					// (ADR-004). Everything on that object is caller-supplied: the body,
					// the parsed arguments, the URI and the host it was addressed to.
					{
						Match:      MatchEntryParamProperty,
						Framework:  "tornado",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"request", "path_args", "path_kwargs"},
					},
					// The METHOD forms of an aiohttp body, which is the only way to read
					// one: it is a coroutine, so there is no property to reach for.
					{Match: MatchCallResult, Symbol: "request.post"},
					{Match: MatchCallResult, Symbol: "request.json"},
					{Match: MatchCallResult, Symbol: "request.text"},
					{Match: MatchCallResult, Symbol: "request.read"},
					{Match: MatchCallResult, Symbol: "request.multipart"},
					{Match: MatchCallResult, Symbol: "flask.request.get_json"},
					{Match: MatchCallResult, Symbol: "flask.request.get_data"},
					{Match: MatchCallResult, Symbol: "request.get_json"},
					{Match: MatchCallResult, Symbol: "request.get_data"},
				},
			},
			{
				// Caller input used only by the timing decision. Keeping this separate
				// from general untrusted-input is a measured precision boundary: adding
				// Tornado get_argument there produced three unrelated JupyterHub findings
				// through approximate external-call flow, two false and one disputed. A
				// comparison rule needs this source; SQL, templates and record ownership
				// do not need a second request model beside the frontend's entry model.
				Class: "caller-comparison-input",
				Label: "a value supplied by the caller for comparison",
				Rules: []SourceRule{
					{
						Match:      MatchEntryParamProperty,
						Framework:  "express",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"query", "body", "params", "headers", "cookies"},
					},
					{
						Match:      MatchEntryParamProperty,
						Framework:  "fastify",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"query", "body", "params", "headers", "cookies"},
					},
					{
						Match:  MatchGlobalProperty,
						Symbol: "flask.request",
						Paths:  []string{"args", "form", "json", "values", "headers", "cookies", "data"},
					},
					// Tornado exposes a request argument through the handler method even
					// when an application passes that handler into a helper. The method is
					// the framework contract; the parameter name before it is application
					// vocabulary and cannot be named by a source rule.
					{Match: MatchCallMethodResult, Method: "get_argument"},
				},
			},
			{
				// Framework dispatch hands these lifecycle hooks data that originated at the
				// request boundary, but no ordinary call edge joins the two. Kept as a
				// separate class and governed only at argv: treating every engine search
				// parameter as general request taint introduced unrelated HTML and log flows.
				Class: "process-argument-input",
				Label: "data supplied to a process-launch lifecycle hook",
				Rules: []SourceRule{
					{Match: MatchFunctionParamProperty, Function: "search", ParamIndex: 0},
					{
						Match: MatchFunctionParamProperty, Function: "add_system_user",
						ParamIndex: 1, Paths: []string{"name"},
					},
				},
			},
			{
				// A caller's data on its way back OUT of a store, which is the only
				// classification here whose origin is in a different request from its
				// sink. Taint is intra-request; a value written to a database by one
				// caller and read back by another arrives looking like something the
				// server established, and the four most serious findings an independent
				// review produced across ten repositories were all that shape.
				//
				// It is declared AFTER untrusted-input on purpose: the strategy reads
				// what that classification concluded, and model order is where the
				// dependency is written down.
				//
				// Only the ORM medium is claimed. Session and browser storage are
				// modelled as stores -- a read out of either answers with what was
				// written, which is what stops a lookup key from poisoning the value it
				// returned -- and neither is claimed as a second-order SOURCE, because a
				// session is one caller's own data coming back to that same caller and
				// `localStorage` never leaves the browser it was written in. Second-order
				// taint is worth having only where the value crosses between principals.
				Class: "second-order-input",
				Label: "data a caller stored in an earlier request",
				Rules: []SourceRule{
					{
						Match: MatchStoreRead, WrittenClass: "untrusted-input", Medium: "orm",
					},
				},
			},
			{
				// The answer a service on the other end of a network call gave. Whoever
				// runs that service wrote the bytes, and a program that parses them is
				// parsing somebody else's text however ordinary the call looks.
				//
				// This is a separate class from request data rather than more of it, for
				// the same reason the stored class is separate: what makes it worth
				// reporting differs. A request is sent by a stranger and this is not
				// necessarily -- an application routinely calls a service it operates
				// itself, and calling your own API is not a vulnerability. The engine
				// cannot read a URL and say whose host it names, so it declines to: the
				// class is labelled by WHERE the value came from, the finding says so in
				// those words, and the denied set is narrowed to the destinations that
				// INTERPRET what they are handed, where the answer does not turn on whose
				// service it was. A response landing in a log or an outbound request is
				// not claimed at all.
				//
				// It does not contradict the client-role judgement one line above; the
				// two are the same fact read in opposite directions. That rule says a key
				// this program PRESENTS to a third party is that party's public
				// configuration and not this program's secret. This one says the answer
				// that party sends BACK is that party's text and not this program's data.
				// Both rest on the third party being outside the trust boundary; they
				// disagree about nothing, because no value is ever both.
				Class: "upstream-response",
				Label: "a response from a service this program called",
				Rules: []SourceRule{
					// The response OBJECT, not one field of it. A body reaches the
					// program through `.json()`, `.text`, `.content`, `.read()` and a
					// dozen other spellings per library, and the receiver rule already
					// carries the class through every one; enumerating the accessors
					// would be a list that goes wrong at the next library.
					{Match: MatchCallResult, Symbol: "requests.get"},
					{Match: MatchCallResult, Symbol: "requests.post"},
					{Match: MatchCallResult, Symbol: "requests.put"},
					{Match: MatchCallResult, Symbol: "requests.patch"},
					{Match: MatchCallResult, Symbol: "requests.delete"},
					{Match: MatchCallResult, Symbol: "requests.head"},
					{Match: MatchCallResult, Symbol: "requests.request"},
					{Match: MatchCallResult, Symbol: "httpx.get"},
					{Match: MatchCallResult, Symbol: "httpx.post"},
					{Match: MatchCallResult, Symbol: "httpx.put"},
					{Match: MatchCallResult, Symbol: "httpx.patch"},
					{Match: MatchCallResult, Symbol: "httpx.delete"},
					{Match: MatchCallResult, Symbol: "httpx.head"},
					{Match: MatchCallResult, Symbol: "httpx.request"},
					{Match: MatchCallResult, Symbol: "urlopen", SymbolLeaf: true},
					{Match: MatchCallResult, Symbol: "fetch"},
					{Match: MatchCallResult, Symbol: "node-fetch"},
					{Match: MatchCallResult, Symbol: "axios"},
					{Match: MatchCallResult, Symbol: "axios.get"},
					{Match: MatchCallResult, Symbol: "axios.post"},
					{Match: MatchCallResult, Symbol: "axios.put"},
					{Match: MatchCallResult, Symbol: "axios.patch"},
					{Match: MatchCallResult, Symbol: "axios.delete"},
					{Match: MatchCallResult, Symbol: "axios.request"},
					// The other half of a contract this model already names. A SearxNG
					// engine module is dispatched by the framework at two points -- it
					// builds a request in `search(query, params)` and it parses the
					// answer in `response(resp)` -- and the first is already declared
					// above, for the same reason: no resolvable call edge joins the
					// framework to the module, so the hook signature IS the boundary.
					// 241 of the 242 functions with this name in that repository are
					// engine modules and every one takes the upstream response as its
					// first parameter.
					{Match: MatchFunctionParamProperty, Function: "response", ParamIndex: 0},
				},
			},
			{
				Class: "actor-identity",
				Label: "the identity of the caller",
				Rules: []SourceRule{
					{
						Match:      MatchEntryParamProperty,
						Framework:  "express",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"user", "session", "auth", "principal"},
					},
					// The same request object, reached through a route the frontend
					// found by its SHAPE rather than by a registration call: a table of
					// `{method, path, handler}` objects, or a helper that takes a verb,
					// a path and a handler. One application in the corpus builds its
					// whole surface that way -- 109 of its 113 entry points -- and
					// every one of them hands the handler an Express request whose
					// `user` a middleware has already established. Nothing here spoke
					// for those routes, so the ownership analysis reported `no source
					// for actor-identity in this program` over an application that
					// consults `req.user` in most of its controllers.
					//
					// Fastify is here for the mirror-image reason: correcting a framework
					// label must not cost coverage the wrong label happened to give. Its
					// request is decorated the same way -- `@fastify/jwt` puts the verified
					// claims on `request.user` -- so the judgement is identical and only
					// the label differs (ADR-004).
					{
						Match:      MatchEntryParamProperty,
						Framework:  "fastify",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"user", "session", "auth", "principal"},
					},
					{
						Match:      MatchEntryParamProperty,
						Framework:  "described-route",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"user", "session", "auth", "principal"},
					},
					{
						Match:      MatchEntryParamProperty,
						Framework:  "helper-route",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"user", "session", "auth", "principal"},
					},
					// Django hangs the authenticated user off the request, and Django
					// REST Framework adds `request.auth` for the credential that
					// established it. A class-based view or a viewset answers in a
					// METHOD, so the request is the second parameter there -- the same
					// two-rule pairing the untrusted-input side already makes for this
					// framework.
					{
						Match:      MatchEntryParamProperty,
						Framework:  "django",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"user", "auth", "session"},
					},
					{
						Match:      MatchEntryParamProperty,
						Framework:  "django",
						EntryKind:  "http-route",
						ParamIndex: 1,
						Paths:      []string{"user", "auth", "session"},
					},
					// A GraphQL resolver is handed the request inside `info.context`,
					// which for a Django-hosted schema IS the HttpRequest -- so the
					// caller's identity is `info.context.user`, and an application
					// authenticated by token puts the App there instead.
					//
					// Two parameter positions because a resolver is written both ways and
					// neither spelling is wrong: `perform_mutation(cls, _root, info)` puts
					// it third and `mutate(root, info)` puts it second. Naming both costs
					// nothing -- the other parameter at each index is a root or an
					// argument map, and neither has a `context` to read.
					{
						Match:      MatchEntryParamProperty,
						Framework:  "graphene",
						EntryKind:  "graphql-operation",
						ParamIndex: 1,
						Paths:      []string{"context"},
						LeafEquals: []string{"user", "app", "auth", "requestor"},
					},
					{
						Match:      MatchEntryParamProperty,
						Framework:  "graphene",
						EntryKind:  "graphql-operation",
						ParamIndex: 2,
						Paths:      []string{"context"},
						LeafEquals: []string{"user", "app", "auth", "requestor"},
					},
					// Tornado hangs it off the HANDLER rather than off the request, so
					// the identity is `self.current_user` and `self` is the verb
					// method's first parameter. Same judgement, different plumbing
					// (ADR-004).
					{
						Match:      MatchEntryParamProperty,
						Framework:  "tornado",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"current_user", "current_user_token"},
					},
					// A token whose signature was CHECKED. That is what makes the claims
					// inside it an established identity rather than something the caller
					// said about themselves: `decode` reads the same fields and proves
					// nothing, which is why it is a weakness of its own (CWE-347) and is
					// deliberately not listed here.
					//
					// This is how an application without a session gets its identity, and
					// an ownership analysis that only knows `req.user` reports NOT
					// EVALUATED on every one of them -- honest, and no use to anybody.
					{Match: MatchCallResult, Symbol: "flask_jwt_extended.get_jwt_identity"},
					{Match: MatchCallResult, Symbol: "flask_login.current_user"},
					// A file route is handed a bare `Request` and nothing else, so an
					// application built on one has nowhere to put an identity and
					// parses, validates and authenticates in a helper of its own:
					//
					//	const { auth, body, error } = await parseRequest(request, schema);
					//
					// The helper is the application's, so no symbol can be named for
					// it and none is: what is named is the property, off the result of
					// a call the handler made with its own request. `auth` is the only
					// leaf that means this in every framework that spells it this way,
					// and the neighbours in the same destructuring -- `body`, `query`,
					// `error` -- are deliberately not identity.
					{
						Match:      MatchEntryCallProperty,
						Framework:  "file-route",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"auth", "user", "currentUser", "session", "principal"},
					},
					{
						Match:      MatchEntryCallProperty,
						Framework:  "next-pages",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"auth", "user", "currentUser", "session", "principal"},
					},
					{
						Match:  MatchGlobalProperty,
						Symbol: "flask.g",
						Paths:  []string{"user", "identity", "principal"},
					},
					{
						// Frameworks that inject identity rather than exposing it on a
						// request object. The frontend decides which parameters those
						// are — from what the decorator's own definition reads, not
						// from its name — and this rule only says that such a parameter
						// IS the caller's identity.
						//
						// A rule, and nothing else. No engine change was needed to make
						// ownership analysis work on a second framework shape, which is
						// the property ADR-004 exists to preserve.
						Match:     MatchValueKind,
						ValueKind: "actor-identity-param",
					},
				},
			},
			{
				Class: "internal-error",
				Label: "internal failure detail",
				Rules: []SourceRule{{
					Match:     MatchValueKind,
					ValueKind: "catch-param",
				}},
			},
			{
				// A field the caller sent that IS a secret. What makes this different from
				// ordinary caller input is not that it is untrusted -- it is that writing
				// it down anywhere durable is a disclosure, whoever sent it.
				Class: "caller-credential",
				Label: "a credential the caller sent",
				Rules: []SourceRule{
					{
						Match:        MatchEntryParamProperty,
						Framework:    "express",
						EntryKind:    "http-route",
						ParamIndex:   0,
						Paths:        []string{"body", "query", "headers", "params"},
						LeafContains: []string{"password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "credential", "authorization"},
						LeafExcept:   []string{"csrf", "xsrf"},
					},
					// The same four request properties on Fastify, which has all four under
					// the same names. Stated separately only because the framework label
					// selects the rule.
					{
						Match:        MatchEntryParamProperty,
						Framework:    "fastify",
						EntryKind:    "http-route",
						ParamIndex:   0,
						Paths:        []string{"body", "query", "headers", "params"},
						LeafContains: []string{"password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "credential", "authorization"},
						LeafExcept:   []string{"csrf", "xsrf"},
					},
					{
						Match:        MatchGlobalProperty,
						Symbol:       "flask.request",
						Paths:        []string{"form", "json", "args", "headers", "values"},
						LeafContains: []string{"password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "credential", "authorization"},
						LeafExcept:   []string{"csrf", "xsrf"},
					},
				},
			},
			{
				// A runtime value this program expects a caller to reproduce exactly. A
				// name is not enough to report anything on its own; it is only one side
				// of the relational timing rule, and the other side must independently be
				// caller-supplied. Call provenance covers the spellings where the value's
				// role is stated by the constructor rather than by a property leaf.
				Class: "computed-secret",
				Label: "a secret or digest the program computed",
				Rules: []SourceRule{
					{Match: MatchCallResult, Symbol: "crypto.createHmac"},
					{Match: MatchCallResult, Symbol: "hmac.new"},
					{Match: MatchCallResult, Symbol: "crypto.createHash"},
					{Match: MatchCallResult, Symbol: "hashlib.sha256"},
					{Match: MatchCallResult, Symbol: "hashlib.sha384"},
					{Match: MatchCallResult, Symbol: "hashlib.sha512"},
					{Match: MatchCallResult, Symbol: "crypto.randomBytes"},
					{Match: MatchCallResult, Symbol: "secrets.token_bytes"},
					{Match: MatchCallResult, Symbol: "secrets.token_hex"},
					{Match: MatchCallResult, Symbol: "secrets.token_urlsafe"},
				},
			},
			{
				// The property twin of the provenance class above. Kept separate because a
				// caller may itself send a field named token; two caller fields are a
				// confirmation even though one has a secret-bearing name. A property on the
				// server side carries this class without carrying caller input.
				Class: "stored-secret",
				Label: "a runtime property holding a secret or digest",
				Rules: []SourceRule{{
					Match:        MatchProperty,
					LeafContains: []string{"secret", "token", "signature", "digest", "hmac", "mac"},
					LeafExcept:   []string{"id", "name", "type", "count", "limit", "length", "algorithm"},
				}},
			},
			{
				// A privilege the CALLER claims to have. The name is the whole evidence
				// and it is enough: a request field called `role` or `isAdmin` is a
				// statement the sender made about themselves, and the server has no
				// reason to believe it.
				Class: "caller-asserted-authority",
				Label: "authority the caller claimed for itself",
				Rules: []SourceRule{
					{
						Match:      MatchEntryParamProperty,
						Framework:  "express",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"body", "query", "params", "headers"},
						LeafEquals: authorityNames,
					},
					{
						Match:      MatchEntryParamProperty,
						Framework:  "fastify",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"body", "query", "params", "headers"},
						LeafEquals: authorityNames,
					},
					{
						Match:      MatchGlobalProperty,
						Symbol:     "flask.request",
						Paths:      []string{"form", "json", "args", "headers", "values"},
						LeafEquals: authorityNames,
					},
				},
			},
			{
				// The same claim carried in a cookie, which is its own weakness: a cookie
				// is a value the browser was handed and hands back, and nothing about
				// getting it back says it came from here.
				Class: "cookie-asserted-authority",
				Label: "authority claimed by a cookie the caller sent back",
				Rules: []SourceRule{
					{
						Match:      MatchEntryParamProperty,
						Framework:  "express",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"cookies", "signedCookies"},
						LeafEquals: cookieAuthorityNames,
					},
					{
						Match:      MatchEntryParamProperty,
						Framework:  "fastify",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"cookies", "signedCookies"},
						LeafEquals: cookieAuthorityNames,
					},
					{
						Match:      MatchGlobalProperty,
						Symbol:     "flask.request",
						Paths:      []string{"cookies"},
						LeafEquals: cookieAuthorityNames,
					},
				},
			},
			{
				// The Referer header, which the browser sends and the caller controls. It
				// says where a request came from only in the sense that it says whatever
				// the sender wrote there.
				Class: "referer",
				Label: "the Referer header the caller sent",
				Rules: []SourceRule{
					{
						Match:      MatchEntryParamProperty,
						Framework:  "express",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"headers"},
						LeafEquals: []string{"referer", "referrer", "origin"},
					},
					{
						Match:      MatchEntryParamProperty,
						Framework:  "fastify",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"headers"},
						LeafEquals: []string{"referer", "referrer", "origin"},
					},
					{
						Match:      MatchGlobalProperty,
						Symbol:     "flask.request",
						Paths:      []string{"referrer", "headers"},
						LeafEquals: []string{"referer", "referrer", "origin"},
					},
				},
			},
			{
				// A name from a reverse lookup, which is controlled by whoever runs the
				// PTR record for the address -- and that is not necessarily whoever runs
				// the name it resolves to.
				Class: "reverse-dns-name",
				Label: "a name from a reverse DNS lookup",
				Rules: []SourceRule{
					{Match: MatchCallResult, Symbol: "dns.reverse"},
					{Match: MatchCallResult, Symbol: "dns/promises.reverse"},
					{Match: MatchCallResult, Symbol: "socket.gethostbyaddr"},
					{Match: MatchCallResult, Symbol: "socket.getfqdn"},
				},
			},
			{
				// A digest from an algorithm anybody can find collisions in. What makes
				// it a weakness is not the call: measured across ten production
				// repositories the call-shape rule that named the ALGORITHM produced 42
				// findings, and an independent reader judged 39 of them worthless -- a
				// rate-limit bucket key, a Wikimedia directory path, an ETag, an
				// exported helper nothing calls, and twenty-six request signatures that
				// a remote site's own protocol demands in MD5 and nothing about this
				// program's security turns on.
				//
				// The three that were worth reporting have one thing in common and it is
				// not the algorithm: the program ESTABLISHES something by the digest. It
				// compares a computed digest against a recorded one, or it tests
				// membership in a list of digests, and a second input that hashes the
				// same defeats the check.
				//
				// So the algorithm is classified here and judged where the digest lands,
				// exactly as a fast random number is: the same call is a cache key in one
				// file and a signature check in the next, and only the second place knows
				// which. A digest that merely leaves the process -- into a URL, a
				// filename, an outbound parameter -- decides nothing here, whoever else
				// reads it.
				Class: "weak-digest",
				Label: "a digest from an algorithm that is broken against collision",
				Rules: []SourceRule{
					{Match: MatchCallResult, Symbol: "hashlib.md5"},
					{Match: MatchCallResult, Symbol: "hashlib.sha1"},
					{Match: MatchCallResult, Symbol: "hashlib.new", ArgOneOf: weakDigest},
					{Match: MatchCallResult, Symbol: "crypto.createHash", ArgOneOf: weakDigest},
					// HMAC is deliberately absent. What makes an HMAC sound is the key
					// and the construction rather than the hash's collision resistance,
					// and HMAC-MD5 has no practical forgery -- so a rule about digests
					// broken against collision has nothing to say about it, and the
					// old shape's answer there was the algorithm's name and nothing
					// more. Stated rather than left to be noticed.
				},
			},
			{
				// A number from a generator that is fast rather than unpredictable. What
				// makes this a weakness is not the call -- Math.random appears 90 times
				// across the clean corpus, almost all of it jitter, sampling and
				// placeholders -- but where the number ENDS UP. So it is classified here
				// and judged at the sink, which is the only place the question can be
				// answered.
				Class: "predictable-value",
				Label: "a number from a generator built for speed rather than unpredictability",
				Rules: []SourceRule{
					{Match: MatchCallResult, Symbol: "Math.random"},
					{Match: MatchCallResult, Symbol: "random.random"},
					{Match: MatchCallResult, Symbol: "random.randint"},
					{Match: MatchCallResult, Symbol: "random.choice"},
					{Match: MatchCallResult, Symbol: "random.randrange"},
				},
			},
			{
				// A random value that is TOO SHORT. How many bytes are enough cannot be
				// answered at the call: measured across the clean corpus, every short
				// one was a unique suffix, a SQL parameter name, a colour, a temporary
				// table name, or a slug checked for collisions in a loop -- 77 findings
				// and not one of them a secret. So the length is recorded here and
				// judged where the value lands, which is the only place that knows
				// whether guessing it matters.
				Class: "short-random-value",
				Label: "a random value written to be shorter than 128 bits",
				Rules: []SourceRule{
					{Match: MatchCallResult, Symbol: "crypto.randomBytes", ArgBelow: atLeast(16)},
					{Match: MatchCallResult, Symbol: "os.urandom", ArgBelow: atLeast(16)},
					{Match: MatchCallResult, Symbol: "secrets.token_bytes", ArgBelow: atLeast(16)},
					{Match: MatchCallResult, Symbol: "secrets.token_hex", ArgBelow: atLeast(16)},
					{Match: MatchCallResult, Symbol: "secrets.token_urlsafe", ArgBelow: atLeast(16)},
					{Match: MatchCallResult, Symbol: "os.getrandom", ArgBelow: atLeast(16)},
				},
			},
			{
				// Facts about a PERSON that are not secrets and are not replaceable. A
				// password can be changed after it leaks; a national identity number, a
				// date of birth and a medical record cannot, which is why they are their
				// own classification rather than more credentials.
				//
				// The vocabulary is short and specific on purpose. Measured across the
				// clean corpus these names appear three times in 28 production
				// repositories, and two of those three are Passport, the authentication
				// library -- which is exactly why `passport` alone is not on this list
				// and `passport_number` is.
				Class: "personal-information",
				Label: "a fact about a person that cannot be reissued",
				Rules: []SourceRule{
					{
						Match:      MatchEntryParamProperty,
						Framework:  "express",
						EntryKind:  "http-route",
						ParamIndex: 0,
						Paths:      []string{"body", "query", "params"},
						LeafEquals: personalNames,
					},
					{
						Match:      MatchGlobalProperty,
						Symbol:     "flask.request",
						Paths:      []string{"form", "json", "args", "values"},
						LeafEquals: personalNames,
					},
				},
			},
			{
				// A value anybody can observe or recompute: the clock, the process id, a
				// counter. None of these are secrets and none of them are meant to be --
				// what makes one a weakness is the same thing that makes a fast random
				// number one, which is where it ENDS UP. `Date.now()` appears everywhere
				// in every corpus and is almost always a timestamp, so it is classified
				// here and judged at the sink.
				Class: "observable-value",
				Label: "a value anyone can observe or recompute, such as the current time",
				Rules: []SourceRule{
					{Match: MatchCallResult, Symbol: "Date.now"},
					{Match: MatchCallResult, Symbol: "performance.now"},
					{Match: MatchCallResult, Symbol: "process.hrtime"},
					{Match: MatchCallResult, Symbol: "process.uptime"},
					{Match: MatchCallResult, Symbol: "time.time"},
					{Match: MatchCallResult, Symbol: "time.time_ns"},
					{Match: MatchCallResult, Symbol: "time.monotonic"},
					{Match: MatchCallResult, Symbol: "time.monotonic_ns"},
					{Match: MatchCallResult, Symbol: "time.perf_counter_ns"},
					{Match: MatchCallResult, Symbol: "time.perf_counter"},
					{Match: MatchCallResult, Symbol: "datetime.datetime.now"},
					{Match: MatchCallResult, Symbol: "datetime.datetime.utcnow"},
					{Match: MatchCallResult, Symbol: "os.getpid"},
					// A version 1 UUID is the clock and the MAC address written down. It
					// looks exactly like a version 4 one and is not a secret at all.
					{Match: MatchCallResult, Symbol: "uuid.uuid1"},
					{Match: MatchCallResult, Symbol: "uuid.v1"},
				},
			},
			{
				// The environment a process was started with is where its secrets are:
				// database URLs, API keys, signing keys. It is also where its harmless
				// configuration is, which is why the policy asks for the whole structure
				// rather than for anything read out of it.
				Class: "system-information",
				Label: "the environment this process was started with",
				Rules: []SourceRule{
					{
						Match:     MatchGlobalProperty,
						Symbol:    "process",
						Paths:     []string{"env"},
						ExactPath: true,
					},
					{
						Match:     MatchGlobalProperty,
						Symbol:    "os",
						Paths:     []string{"environ"},
						ExactPath: true,
					},
				},
			},
		},

		// WHAT CHANNELS ARE. Visibility and interpreted context, not danger.
		Channels: []Channel{
			// A regular expression the caller writes. Backtracking engines can be made
			// to take exponential time on a short input, so a pattern from outside is a
			// way to stop the process without touching it.
			{
				ID: "regex-compiler", Visibility: "internal", Context: "regex",
				Symbol: "RegExp", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1333",
				Rationale: "the first argument is compiled as a pattern",
			},
			{
				ID: "regex-compiler", Visibility: "internal", Context: "regex",
				Symbol: "re.compile", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1333",
				Rationale: "the first argument is compiled as a pattern",
			},

			// A redirect the caller writes. The browser follows it, so the application
			// lends its own name to a destination someone else chose -- which is what
			// makes a phishing link look like it came from you.
			//
			// Whole value, for the same reason SSRF is: `redirect("/users/" + id)` is a
			// path within this application and cannot leave it.
			{
				ID: "redirect-destination", Visibility: "public", Context: "redirect",
				Method: "redirect", ReceiverIsEntryParam: 1, ArgIndex: []int{0},
				CWE:                "CWE-601",
				RequiresWholeValue: true,
				Rationale:          "the browser is told to go wherever this names",
			},
			{
				ID: "redirect-destination", Visibility: "public", Context: "redirect",
				Symbol: "flask.redirect", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-601",
				RequiresWholeValue: true,
				Rationale:          "the browser is told to go wherever this names",
			},

			// Deserializers that reconstruct arbitrary objects. Not a parser: these call
			// constructors, and a payload can therefore choose what runs.
			{
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "node-serialize.unserialize", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-502",
				Rationale: "unserialize() reconstructs objects, including functions it then invokes",
			},
			{
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "pickle.loads", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-502",
				Rationale: "pickle reconstructs arbitrary objects by calling their constructors",
			},
			{
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "pickle.load", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"file": 0},
				CWE:             "CWE-502",
				Rationale:       "pickle reconstructs arbitrary objects by calling their constructors",
			},
			{
				// yaml.load without an explicit safe loader constructs Python objects.
				// yaml.safe_load is a different symbol and is deliberately absent.
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "yaml.load", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"stream": 0},
				CWE:             "CWE-502",
				Rationale:       "yaml.load constructs Python objects unless given a safe loader",
			},
			{
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "yaml.unsafe_load", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"stream": 0},
				CWE:             "CWE-502",
				Rationale:       "the name is the documentation: this loader constructs whatever the document names",
			},
			{
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "yaml.full_load", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"stream": 0},
				CWE:             "CWE-502",
				Rationale:       "the full loader constructs arbitrary Python objects",
			},
			{
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "marshal.loads", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-502",
				Rationale: "marshal reads code objects and validates nothing about the format",
			},
			{
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "jsonpickle.decode", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"string": 0},
				CWE:             "CWE-502",
				Rationale:       "jsonpickle reconstructs objects by importing the classes the document names",
			},
			{
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "dill.loads", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"str": 0},
				CWE:             "CWE-502",
				Rationale:       "dill extends pickle and reconstructs arbitrary objects the same way",
			},
			{
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "shelve.open", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"filename": 0},
				CWE:             "CWE-502",
				Rationale:       "a shelf is a pickle file, so opening one the caller named unpickles what it holds",
			},

			// Where an outbound request GOES, as opposed to what it carries. The same
			// axios.post is two different destinations depending on which argument is
			// being asked about: argument 1 is data leaving the trust boundary, and
			// argument 0 is the caller choosing which machine the application talks to
			// from inside the network. Different arguments, different judgements, one
			// call.
			// A caller's string tested against a pattern that can be made to churn. The
			// pattern is where the call says it is: the receiver for `RE.test(s)`, the
			// first argument for Python's module-level functions.
			{
				ID: "regex-subject", Visibility: "internal", Context: "regex-subject",
				Method: "test", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				PatternArg: at(-1),
				CWE:        "CWE-1333",
				Rationale:  "the pattern this is tested against has a quantified group with a quantifier inside it",
			},
			{
				ID: "regex-subject", Visibility: "internal", Context: "regex-subject",
				Method: "exec", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				PatternArg: at(-1),
				CWE:        "CWE-1333",
				Rationale:  "the pattern this is run against has a quantified group with a quantifier inside it",
			},
			// JavaScript's spelling, which reverses the operands: the SUBJECT is the
			// receiver and the pattern is the argument. `req.body.value.match(/(a+)+/)`
			// is the ordinary way to write this in the language and the model described
			// only the other direction, so the most common shape was invisible.
			{
				ID: "regex-subject", Visibility: "internal", Context: "regex-subject",
				Method: "match", ReceiverIsEntryParam: -1, RequiresUntrustedReceiver: true,
				Language:   "typescript",
				PatternArg: at(0),
				CWE:        "CWE-1333",
				Rationale:  "the pattern this string is matched against has a quantified group with a quantifier inside it",
			},
			{
				ID: "regex-subject", Visibility: "internal", Context: "regex-subject",
				Method: "matchAll", ReceiverIsEntryParam: -1, RequiresUntrustedReceiver: true,
				Language:   "typescript",
				PatternArg: at(0),
				CWE:        "CWE-1333",
				Rationale:  "the pattern this string is matched against has a quantified group with a quantifier inside it",
			},
			{
				ID: "regex-subject", Visibility: "internal", Context: "regex-subject",
				Method: "search", ReceiverIsEntryParam: -1, RequiresUntrustedReceiver: true,
				Language:   "typescript",
				PatternArg: at(0),
				CWE:        "CWE-1333",
				Rationale:  "the pattern this string is searched with has a quantified group with a quantifier inside it",
			},
			{
				ID: "regex-subject", Visibility: "internal", Context: "regex-subject",
				Method: "replace", ReceiverIsEntryParam: -1, RequiresUntrustedReceiver: true,
				Language:   "typescript",
				PatternArg: at(0),
				CWE:        "CWE-1333",
				Rationale:  "the pattern this string is rewritten with has a quantified group with a quantifier inside it",
			},
			// The compiled form, which is how Python is normally written: `PATTERN =
			// re.compile(...)` at module scope and `PATTERN.match(value)` in the handler.
			// The pattern is the receiver and it is a call result, so finding it means
			// following the receiver through the compile step.
			{
				ID: "regex-subject", Visibility: "internal", Context: "regex-subject",
				Method: "match", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				// Python's. JavaScript reverses the operands -- `subject.match(pattern)`
				// -- so without this a string literal that happens to be a catastrophic
				// pattern would be read as the subject's pattern and the short constant
				// receiver as the caller's text.
				Language:   "python",
				PatternArg: at(-1),
				CWE:        "CWE-1333",
				Rationale:  "the compiled pattern this is matched against has a quantified group with a quantifier inside it",
			},
			{
				ID: "regex-subject", Visibility: "internal", Context: "regex-subject",
				Method: "search", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				// Python's. JavaScript reverses the operands -- `subject.match(pattern)`
				// -- so without this a string literal that happens to be a catastrophic
				// pattern would be read as the subject's pattern and the short constant
				// receiver as the caller's text.
				Language:   "python",
				PatternArg: at(-1),
				CWE:        "CWE-1333",
				Rationale:  "the compiled pattern this is searched with has a quantified group with a quantifier inside it",
			},
			{
				ID: "regex-subject", Visibility: "internal", Context: "regex-subject",
				Method: "fullmatch", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				// Python's. JavaScript reverses the operands -- `subject.match(pattern)`
				// -- so without this a string literal that happens to be a catastrophic
				// pattern would be read as the subject's pattern and the short constant
				// receiver as the caller's text.
				Language:   "python",
				PatternArg: at(-1),
				CWE:        "CWE-1333",
				Rationale:  "the compiled pattern this is matched against has a quantified group with a quantifier inside it",
			},
			{
				ID: "regex-subject", Visibility: "internal", Context: "regex-subject",
				Symbol: "re.match", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				PatternArg: at(0),
				CWE:        "CWE-1333",
				Rationale:  "the pattern this is matched against has a quantified group with a quantifier inside it",
			},
			{
				ID: "regex-subject", Visibility: "internal", Context: "regex-subject",
				Symbol: "re.search", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				PatternArg: at(0),
				CWE:        "CWE-1333",
				Rationale:  "the pattern this is searched with has a quantified group with a quantifier inside it",
			},
			{
				ID: "regex-subject", Visibility: "internal", Context: "regex-subject",
				Symbol: "re.fullmatch", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				PatternArg: at(0),
				CWE:        "CWE-1333",
				Rationale:  "the pattern this is matched against has a quantified group with a quantifier inside it",
			},
			// A glob pattern is a small language, and these APIs interpret it themselves.
			// A caller who writes `**/*` walks the whole tree from wherever the program
			// started; one who writes a character class reads names it was never offered.
			// Choosing a PATTERN and choosing a PATH are not the same weakness, which is
			// why they are reported apart.
			{
				ID: "glob-pattern", Visibility: "internal", Context: "glob",
				Symbol: "glob.glob", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-155",
				Rationale: "glob() interprets its argument as a wildcard pattern",
			},
			{
				ID: "glob-pattern", Visibility: "internal", Context: "glob",
				Symbol: "glob.iglob", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-155",
				Rationale: "iglob() interprets its argument as a wildcard pattern",
			},
			{
				ID: "glob-pattern", Visibility: "internal", Context: "glob",
				Symbol: "pathlib.Path.glob", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-155",
				Rationale: "glob() interprets its argument as a wildcard pattern",
			},
			{
				ID: "glob-pattern", Visibility: "internal", Context: "glob",
				Symbol: "glob.default", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-155",
				Rationale: "glob() interprets its argument as a wildcard pattern",
			},
			{
				ID: "glob-pattern", Visibility: "internal", Context: "glob",
				Symbol: "fast-glob.default", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-155",
				Rationale: "glob() interprets its argument as a wildcard pattern",
			},
			// XML a caller's text was BUILT INTO. Not a protocol the engine models: the
			// composition is the evidence, exactly as it is for SQL, and the language
			// ships the escaper that says so.
			{
				ID: "xml-document", Visibility: "internal", Context: "xml-composed",
				Symbol: "lxml.etree.fromstring", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresComposition: true,
				CWE:                 "CWE-91",
				Rationale:           "the first argument is parsed as an XML document",
			},
			{
				ID: "xml-document", Visibility: "internal", Context: "xml-composed",
				Symbol: "xml.etree.ElementTree.fromstring", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresComposition: true,
				CWE:                 "CWE-91",
				Rationale:           "the first argument is parsed as an XML document",
			},
			{
				ID: "xml-document", Visibility: "internal", Context: "xml-composed",
				Symbol: "libxmljs.parseXmlString", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresComposition: true,
				CWE:                 "CWE-91",
				Rationale:           "the first argument is parsed as an XML document",
			},
			{
				ID: "xml-document", Visibility: "internal", Context: "xml-composed",
				Symbol: "xml2js.parseString", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresComposition: true,
				CWE:                 "CWE-91",
				Rationale:           "the first argument is parsed as an XML document",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "axios.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "axios.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "axios.put", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "axios.delete", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "axios.request", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "node-fetch.default", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "http.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "http.request", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "https.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "https.request", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "got.default", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			// Clients the list did not have. `needle` carries one of the two server-side
			// request forgeries a recall audit named and was simply absent, which is the
			// failure mode a symbol list has: it is right about everything it mentions and
			// silent about everything it does not, and the silence looks the same as a
			// clean result. The rest are the remaining verbs of clients already listed and
			// the two async clients Python code reaches for most.
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "needle.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "needle.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "needle.put", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "needle.head", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "needle.request", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "undici.request", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "undici.fetch", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "ky.default", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "phin.default", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "axios.patch", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "axios.head", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "requests.patch", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword:      map[string]int{"url": 0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "requests.options", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword:      map[string]int{"url": 0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			// The verb-as-argument spelling, and the one a PROXY is always written in:
			// a handler that forwards whatever method arrived cannot call `get`. Both of
			// these put the destination in the SECOND argument, behind the method --
			// `requests.request(method, url, ...)` -- and the entry the list already had
			// named argument zero, which is the verb and never the address. archivebox's
			// `/opencode/<path>` proxy is `requests.request(method, _proxy_url(...))` and
			// had no channel at all: `requests.request` was absent from this list, and
			// the httpx spelling of the same call pointed at the wrong slot.
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "requests.request", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				RequiredKeyword:      map[string]int{"url": 1},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the second argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "httpx.request", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				RequiredKeyword:      map[string]int{"url": 1},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the second argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "httpx.put", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword:      map[string]int{"url": 0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "httpx.delete", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword:      map[string]int{"url": 0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "aiohttp.ClientSession.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword:      map[string]int{"url": 0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "aiohttp.ClientSession.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword:      map[string]int{"url": 0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "superagent.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "requests.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword:      map[string]int{"url": 0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "requests.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword:      map[string]int{"url": 0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "requests.put", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword:      map[string]int{"url": 0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "requests.delete", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword:      map[string]int{"url": 0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "requests.head", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword:      map[string]int{"url": 0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "urllib.request.urlopen", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword:      map[string]int{"url": 0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "httpx.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword:      map[string]int{"url": 0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "httpx.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword:      map[string]int{"url": 0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "fetch", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                  "CWE-918",
				RequiresWholeValue:   true,
				AllowsComposedPrefix: true,
				Rationale:            "the first argument is the address this request is sent to",
			},
			// The filesystem, addressed by a path the caller chose. A read is not an
			// interpreter and this is not injection: nothing is executed, a different
			// file is simply opened than the one intended. Its own context and its own
			// policy, because it is its own judgement.
			// Handing a caller's whole object to something that writes records. The
			// weakness is not that a field is untrusted -- they all are -- but that the
			// application never said WHICH fields it meant to accept.
			//
			// Deliberately ONE shape. `update`, `create` and `save` were tried and
			// withdrawn: `save` is what an uploaded file is written with, `update` is
			// already how a record is SELECTED by its identifier, and a dict has all
			// three. Telling a model apart from a dictionary needs the receiver's type,
			// which neither frontend reliably has -- so this is matched where the symbol
			// leaves no room for doubt, and the ledger says what that costs.
			{
				ID: "record-writer", Visibility: "internal", Context: "record-fields",
				Symbol: "Object.assign", ReceiverIsEntryParam: -1, ArgIndex: []int{1, 2, 3},
				TargetArg: arg(0), RequiresUnenclosed: true,
				CWE:       "CWE-915",
				Rationale: "assign() copies every key of the caller's object onto the target",
			},

			// Choosing WHICH code runs, rather than writing code for it to run. Nothing is
			// interpreted here: the caller names a module or a class and the runtime goes
			// and loads it, which reaches every path the process can read and every
			// side effect that loading has.
			{
				ID: "module-loader", Visibility: "internal", Context: "code",
				Symbol: "require", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresWholeValue: true,
				CWE:                "CWE-470",
				Rationale:          "require() loads and runs whatever module this names",
			},
			{
				ID: "module-loader", Visibility: "internal", Context: "code",
				Symbol: "importlib.import_module", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresWholeValue: true,
				CWE:                "CWE-470",
				Rationale:          "import_module() imports and runs whatever module this names",
			},
			{
				ID: "module-loader", Visibility: "internal", Context: "code",
				Symbol: "builtins.__import__", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresWholeValue: true,
				CWE:                "CWE-470",
				Rationale:          "__import__() imports and runs whatever module this names",
			},

			// Merging a caller's object into another one is mass assignment with a
			// sharper edge: these functions walk nested keys, so `__proto__` in the
			// caller's object reaches the prototype every other object inherits from.
			{
				ID: "deep-merge", Visibility: "internal", Context: "record-fields",
				Symbol: "lodash.merge", ReceiverIsEntryParam: -1, ArgIndex: []int{1, 2, 3},
				TargetArg: arg(0), RequiresUnenclosed: true,
				CWE:       "CWE-1321",
				Rationale: "merge() walks nested keys, so a __proto__ key in the source reaches the prototype",
			},
			{
				ID: "deep-merge", Visibility: "internal", Context: "record-fields",
				Symbol: "lodash.merge.default", ReceiverIsEntryParam: -1, ArgIndex: []int{1, 2, 3},
				TargetArg: arg(0), RequiresUnenclosed: true,
				CWE:       "CWE-1321",
				Rationale: "merge() walks nested keys, so a __proto__ key in the source reaches the prototype",
			},
			{
				ID: "deep-merge", Visibility: "internal", Context: "record-fields",
				Symbol: "lodash.defaultsDeep", ReceiverIsEntryParam: -1, ArgIndex: []int{1, 2, 3},
				TargetArg: arg(0), RequiresUnenclosed: true,
				CWE:       "CWE-1321",
				Rationale: "defaultsDeep() walks nested keys, so a __proto__ key in the source reaches the prototype",
			},
			{
				ID: "deep-merge", Visibility: "internal", Context: "record-fields",
				Symbol: "deepmerge", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1},
				RequiresUnenclosed: true,
				CWE:                "CWE-1321",
				Rationale:          "deepmerge() walks nested keys, so a __proto__ key in the source reaches the prototype",
			},

			// A spreadsheet does not treat a cell beginning `=`, `+`, `-` or `@` as text.
			// Whoever opens the export runs it, on their machine, with their access --
			// which is why the damage lands somewhere the exporting application never
			// sees.
			{
				ID: "spreadsheet-cell", Visibility: "thirdparty", Context: "csv",
				Method: "writerow", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1236",
				Rationale: "writerow() writes a row a spreadsheet will later interpret",
			},
			{
				ID: "spreadsheet-cell", Visibility: "thirdparty", Context: "csv",
				Method: "writerows", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1236",
				Rationale: "writerows() writes rows a spreadsheet will later interpret",
			},
			{
				ID: "spreadsheet-cell", Visibility: "thirdparty", Context: "csv",
				Symbol: "papaparse.unparse", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1236",
				Rationale: "unparse() builds a CSV a spreadsheet will later interpret",
			},

			// The same destinations as the SSRF channels above, described a second time
			// WITHOUT the whole-value requirement.
			//
			// Visibility is INTERNAL on purpose even though a request leaves the process.
			// Visibility is how the disclosure policies find their sinks, and marking
			// these third-party pulled the environment rule onto them -- which reported
			// "process environment exposed" carrying this channel's CWE number, a finding
			// whose text and identity disagreed. What this channel is about is the
			// CONTEXT, and the policy that uses it names that instead.
			//
			// That requirement is right for server-side request forgery and wrong here,
			// and the difference is what the two judgements ask. SSRF asks whether the
			// caller can move the request to another machine, which a value composed into
			// a fixed base cannot do. This asks what is IN the URL, and a credential
			// concatenated onto the end of one is precisely the case -- so the constraint
			// that makes the first rule precise would make this one blind.
			{
				ID: "outbound-url", Visibility: "internal", Context: "url-query",
				Method: "redirect", ReceiverIsEntryParam: 1, ArgIndex: []int{0},
				CWE:       "CWE-598",
				Rationale: "the browser is sent to this URL, and it will appear in its history",
			},
			{
				ID: "outbound-url", Visibility: "internal", Context: "url-query",
				Symbol: "axios.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-598",
				Rationale: "the first argument is the URL this request is sent to",
			},
			{
				ID: "outbound-url", Visibility: "internal", Context: "url-query",
				Symbol: "axios.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-598",
				Rationale: "the first argument is the URL this request is sent to",
			},
			{
				ID: "outbound-url", Visibility: "internal", Context: "url-query",
				Symbol: "axios.put", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-598",
				Rationale: "the first argument is the URL this request is sent to",
			},
			{
				ID: "outbound-url", Visibility: "internal", Context: "url-query",
				Symbol: "axios.delete", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-598",
				Rationale: "the first argument is the URL this request is sent to",
			},
			{
				ID: "outbound-url", Visibility: "internal", Context: "url-query",
				Symbol: "node-fetch.default", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-598",
				Rationale: "the first argument is the URL this request is sent to",
			},
			{
				ID: "outbound-url", Visibility: "internal", Context: "url-query",
				Symbol: "fetch", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-598",
				Rationale: "the first argument is the URL this request is sent to",
			},
			{
				ID: "outbound-url", Visibility: "internal", Context: "url-query",
				Symbol: "requests.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"url": 0},
				CWE:             "CWE-598",
				Rationale:       "the first argument is the URL this request is sent to",
			},
			{
				ID: "outbound-url", Visibility: "internal", Context: "url-query",
				Symbol: "requests.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"url": 0},
				CWE:             "CWE-598",
				Rationale:       "the first argument is the URL this request is sent to",
			},
			{
				ID: "outbound-url", Visibility: "internal", Context: "url-query",
				Symbol: "http.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-598",
				Rationale: "the first argument is the URL this request is sent to",
			},
			{
				ID: "outbound-url", Visibility: "internal", Context: "url-query",
				Symbol: "https.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-598",
				Rationale: "the first argument is the URL this request is sent to",
			},

			// A response HEADER value. A carriage return and newline end the header and
			// start whatever the caller writes next -- another header, or the body.
			{
				ID: "response-header", Visibility: "public", Context: "header",
				Method: "setHeader", ReceiverIsEntryParam: 1, ArgIndex: []int{1},
				CWE:       "CWE-93",
				Rationale: "the second argument to setHeader() is the header value",
			},
			{
				ID: "response-header", Visibility: "public", Context: "header",
				Method: "header", ReceiverIsEntryParam: 1, ArgIndex: []int{1},
				CWE:       "CWE-93",
				Rationale: "the second argument to header() is the header value",
			},
			{
				ID: "response-header", Visibility: "public", Context: "header",
				Method: "set", ReceiverIsEntryParam: 1, ArgIndex: []int{1},
				CWE:       "CWE-93",
				Rationale: "the second argument to set() is the header value",
			},

			// What gets WRITTEN to a file. Named by symbol rather than by the `write`
			// method, because `res.write` is a response body and putting both under one
			// method name would report a credential in a response as a credential on
			// disk.
			{
				ID: "file-contents", Visibility: "internal", Context: "storage",
				Symbol: "fs.writeFile", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				Rationale: "the second argument is what gets written to the file",
			},
			{
				ID: "file-contents", Visibility: "internal", Context: "storage",
				Symbol: "fs.writeFileSync", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				Rationale: "the second argument is what gets written to the file",
			},
			{
				ID: "file-contents", Visibility: "internal", Context: "storage",
				Symbol: "fs.appendFile", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				Rationale: "the second argument is what gets written to the file",
			},
			{
				ID: "file-contents", Visibility: "internal", Context: "storage",
				Symbol: "fs.appendFileSync", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				Rationale: "the second argument is what gets written to the file",
			},
			{
				ID: "file-contents", Visibility: "internal", Context: "storage",
				Symbol: "fs/promises.writeFile", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				Rationale: "the second argument is what gets written to the file",
			},
			{
				ID: "file-contents", Visibility: "internal", Context: "storage",
				Symbol: "fs/promises.appendFile", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				Rationale: "the second argument is what gets written to the file",
			},

			// How much memory to reserve, chosen by the caller. One request asking for a
			// gigabyte is not a crash the caller had to find; it is one they asked for.
			{
				ID: "allocation-size", Visibility: "internal", Context: "allocation",
				Symbol: "Buffer.alloc", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-789",
				Rationale: "the first argument is how many bytes to reserve",
			},
			{
				ID: "allocation-size", Visibility: "internal", Context: "allocation",
				Symbol: "Buffer.allocUnsafe", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-789",
				Rationale: "the first argument is how many bytes to reserve",
			},
			{
				ID: "allocation-size", Visibility: "internal", Context: "allocation",
				Symbol: "Buffer.allocUnsafeSlow", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-789",
				Rationale: "the first argument is how many bytes to reserve",
			},

			// Where a generator is TOLD what to start from. A seed decides every number
			// that follows it, so a seed anybody can recompute is a sequence anybody can
			// recompute.
			{
				ID: "prng-seed", Visibility: "internal", Context: "prng-seed",
				Symbol: "random.seed", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-337",
				Rationale: "the argument is the seed",
			},
			{
				ID: "prng-seed", Visibility: "internal", Context: "prng-seed",
				Symbol: "numpy.random.default_rng", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-337",
				Rationale: "the argument is the seed the generator starts from",
			},
			{
				ID: "prng-seed", Visibility: "internal", Context: "prng-seed",
				Symbol: "numpy.random.RandomState", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-337",
				Rationale: "the argument is the seed the generator starts from",
			},
			{
				ID: "prng-seed", Visibility: "internal", Context: "prng-seed",
				Symbol: "numpy.random.seed", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-337",
				Rationale: "the argument is the seed",
			},
			{
				ID: "prng-seed", Visibility: "internal", Context: "prng-seed",
				Symbol: "random.Random", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-337",
				Rationale: "the argument is the seed the generator starts from",
			},
			{
				ID: "prng-seed", Visibility: "internal", Context: "prng-seed",
				Symbol: "faker.seed", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-337",
				Rationale: "the argument is the seed",
			},
			{
				ID: "prng-seed", Visibility: "internal", Context: "prng-seed",
				Symbol: "Math.seedrandom", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-337",
				Rationale: "the argument is the seed",
			},
			{
				// A default export called directly, which is how the seeded generator
				// most Node projects reach for is imported.
				ID: "prng-seed", Visibility: "internal", Context: "prng-seed",
				Symbol: "seedrandom.default", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-337",
				Rationale: "the argument is the seed",
			},

			// A cache outlives the request that filled it and is usually shared: another
			// process, another host, a managed service somebody else runs. A credential
			// put there is a credential in all of those.
			{
				ID: "cache-entry", Visibility: "internal", Context: "cache",
				Method: "set", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				RequiresExternalReceiver: true,
				CWE:                      "CWE-524",
				Rationale:                "the second argument is what the cache will hold",
			},
			{
				ID: "cache-entry", Visibility: "internal", Context: "cache",
				Method: "setex", ReceiverIsEntryParam: -1, ArgIndex: []int{2},
				RequiresExternalReceiver: true,
				CWE:                      "CWE-524",
				Rationale:                "the third argument is what the cache will hold",
			},
			{
				ID: "cache-entry", Visibility: "internal", Context: "cache",
				Method: "hset", ReceiverIsEntryParam: -1, ArgIndex: []int{2},
				RequiresExternalReceiver: true,
				CWE:                      "CWE-524",
				Rationale:                "the third argument is what the cache will hold",
			},

			// A password put through a hash that takes no salt. The digest is then a
			// pure function of the password, which is what makes one precomputed table
			// work against every account in the database at once.
			//
			// The whole-value requirement IS the rule rather than a precision measure:
			// `sha256(password + salt)` composes the password with something else, and
			// something else is what a salt is. Only a password handed over WHOLE is a
			// password hashed with nothing added.
			{
				ID: "unsalted-hash", Visibility: "internal", Context: "unsalted-digest",
				Symbol: "hashlib.md5", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresWholeValue: true,
				CWE:                "CWE-759",
				Rationale:          "md5() takes the data and nothing else, so there is nowhere for a salt to go",
			},
			{
				ID: "unsalted-hash", Visibility: "internal", Context: "unsalted-digest",
				Symbol: "hashlib.sha1", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresWholeValue: true,
				CWE:                "CWE-759",
				Rationale:          "sha1() takes the data and nothing else, so there is nowhere for a salt to go",
			},
			{
				ID: "unsalted-hash", Visibility: "internal", Context: "unsalted-digest",
				Symbol: "hashlib.sha224", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresWholeValue: true,
				CWE:                "CWE-759",
				Rationale:          "sha224() takes the data and nothing else, so there is nowhere for a salt to go",
			},
			{
				ID: "unsalted-hash", Visibility: "internal", Context: "unsalted-digest",
				Symbol: "hashlib.sha256", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresWholeValue: true,
				CWE:                "CWE-759",
				Rationale:          "sha256() takes the data and nothing else, so there is nowhere for a salt to go",
			},
			{
				ID: "unsalted-hash", Visibility: "internal", Context: "unsalted-digest",
				Symbol: "hashlib.sha384", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresWholeValue: true,
				CWE:                "CWE-759",
				Rationale:          "sha384() takes the data and nothing else, so there is nowhere for a salt to go",
			},
			{
				ID: "unsalted-hash", Visibility: "internal", Context: "unsalted-digest",
				Symbol: "hashlib.sha512", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresWholeValue: true,
				CWE:                "CWE-759",
				Rationale:          "sha512() takes the data and nothing else, so there is nowhere for a salt to go",
			},
			{
				ID: "unsalted-hash", Visibility: "internal", Context: "unsalted-digest",
				Symbol: "hashlib.sha3_224", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresWholeValue: true,
				CWE:                "CWE-759",
				Rationale:          "sha3_224() takes the data and nothing else, so there is nowhere for a salt to go",
			},
			{
				ID: "unsalted-hash", Visibility: "internal", Context: "unsalted-digest",
				Symbol: "hashlib.sha3_256", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresWholeValue: true,
				CWE:                "CWE-759",
				Rationale:          "sha3_256() takes the data and nothing else, so there is nowhere for a salt to go",
			},
			{
				ID: "unsalted-hash", Visibility: "internal", Context: "unsalted-digest",
				Symbol: "hashlib.sha3_384", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresWholeValue: true,
				CWE:                "CWE-759",
				Rationale:          "sha3_384() takes the data and nothing else, so there is nowhere for a salt to go",
			},
			{
				ID: "unsalted-hash", Visibility: "internal", Context: "unsalted-digest",
				Symbol: "hashlib.sha3_512", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresWholeValue: true,
				CWE:                "CWE-759",
				Rationale:          "sha3_512() takes the data and nothing else, so there is nowhere for a salt to go",
			},
			{
				// `new` takes the algorithm first and the data second.
				ID: "unsalted-hash", Visibility: "internal", Context: "unsalted-digest",
				Symbol: "hashlib.new", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				RequiresWholeValue: true,
				CWE:                "CWE-759",
				Rationale:          "new() takes the algorithm and the data, and no salt",
			},
			{
				// Node puts the data in a separate call from the algorithm, so the
				// method name alone says nothing and what made the receiver says
				// everything.
				ID: "unsalted-hash", Visibility: "internal", Context: "unsalted-digest",
				Method: "update", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				ReceiverFrom:       []string{"createHash"},
				RequiresWholeValue: true,
				CWE:                "CWE-759",
				Rationale:          "the object being updated came out of createHash, which takes an algorithm and no salt",
			},

			// A call whose whole purpose is to establish that two values are the same
			// one. Whatever is handed to it is being TRUSTED: the program has no other
			// evidence and this answer decides.
			//
			// The context is what the destination does with the value rather than what
			// it parses, which is the same reading `unsalted-digest` and `prng-seed`
			// already take. It is deliberately not "comparison": an ordinary `==` is a
			// comparison and is read from the IR's comparison list, where the class of
			// each side is already known. These are the calls a careful program uses
			// INSTEAD of the operator, and a rule that only watched the operator would
			// go quiet exactly where the author was being careful.
			{
				ID: "digest-verification", Visibility: "internal", Context: "proof",
				Symbol: "hmac.compare_digest", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1},
				CWE:       "CWE-328",
				Rationale: "compare_digest exists to decide whether two digests are the same, and the answer is the whole evidence",
			},
			{
				ID: "digest-verification", Visibility: "internal", Context: "proof",
				Symbol: "secrets.compare_digest", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1},
				CWE:       "CWE-328",
				Rationale: "compare_digest exists to decide whether two digests are the same, and the answer is the whole evidence",
			},
			{
				ID: "digest-verification", Visibility: "internal", Context: "proof",
				Symbol: "crypto.timingSafeEqual", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1},
				CWE:       "CWE-328",
				Rationale: "timingSafeEqual exists to decide whether two digests are the same, and the answer is the whole evidence",
			},
			{
				ID: "digest-verification", Visibility: "internal", Context: "proof",
				Symbol: "django.utils.crypto.constant_time_compare", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1},
				CWE:       "CWE-328",
				Rationale: "constant_time_compare exists to decide whether two values are the same, and the answer is the whole evidence",
			},

			// Turning a password into something REVERSIBLE. Encoding is not hiding and
			// encryption is not hashing: both leave a value that can be turned back into
			// the password by whoever holds what is needed, which for a stored password
			// is the whole problem.
			{
				ID: "reversible-encoding", Visibility: "internal", Context: "reversible",
				Symbol: "btoa", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-261",
				Rationale: "base64 is an encoding and turns straight back into what went in",
			},
			{
				ID: "reversible-encoding", Visibility: "internal", Context: "reversible",
				Symbol: "base64.b64encode", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-261",
				Rationale: "base64 is an encoding and turns straight back into what went in",
			},
			{
				ID: "reversible-encoding", Visibility: "internal", Context: "reversible",
				Symbol: "base64.encodebytes", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-261",
				Rationale: "base64 is an encoding and turns straight back into what went in",
			},
			{
				ID: "reversible-cipher", Visibility: "internal", Context: "recoverable",
				Symbol: "crypto.publicEncrypt", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				CWE:       "CWE-257",
				Rationale: "encryption is reversible by design, which is what a stored password must not be",
			},
			{
				ID: "reversible-cipher", Visibility: "internal", Context: "recoverable",
				// By METHOD: a cipher is always a bound object rather than the module,
				// so the symbol is whatever the instance was called. `encrypt` is
				// distinctive, and the classification does the narrowing -- this only
				// fires when what is being encrypted is a password.
				Method: "encrypt", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-257",
				Rationale: "encryption is reversible by design, which is what a stored password must not be",
			},

			// Where the interpreter loads modules FROM. Putting a caller-controlled
			// directory at the front of it means the next import takes whatever is in
			// that directory, under whatever name it expects.
			// By SYMBOL, not by method name. `insert` and `append` belong to every list,
			// every ORM repository and every zip archive: matched by name they produced
			// eight findings across the clean corpus and not one was a search path --
			// `em.insert`, `archive.append`, `errors.append`. The attribute chain resolves
			// now, so the receiver can be named outright.
			{
				ID: "module-search-path", Visibility: "internal", Context: "search-path",
				Symbol: "sys.path.insert", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				CWE:       "CWE-426",
				Rationale: "inserting into sys.path decides where the next import comes from",
			},
			{
				ID: "module-search-path", Visibility: "internal", Context: "search-path",
				Symbol: "sys.path.append", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-426",
				Rationale: "appending to sys.path decides where an import may come from",
			},

			// The BODY of an outbound request whose destination is written into the call
			// as a plaintext URL. The qualifier is the whole rule: `https://` is not a
			// finding and does not contain `http://`, so the same channel says nothing
			// about the overwhelming majority of outbound calls.
			{
				ID: "plaintext-outbound-body", Visibility: "thirdparty", Context: "plaintext-url",
				Symbol: "axios.post", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				Qualifiers: []ArgCondition{{ArgIndex: 0, AnyOf: []string{"http://"}, Substring: true}},
				CWE:        "CWE-319",
				Rationale:  "the destination is written into the call as a plaintext URL",
			},
			{
				ID: "plaintext-outbound-body", Visibility: "thirdparty", Context: "plaintext-url",
				Symbol: "axios.put", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				Qualifiers: []ArgCondition{{ArgIndex: 0, AnyOf: []string{"http://"}, Substring: true}},
				CWE:        "CWE-319",
				Rationale:  "the destination is written into the call as a plaintext URL",
			},
			{
				ID: "plaintext-outbound-body", Visibility: "thirdparty", Context: "plaintext-url",
				Symbol: "requests.post", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				RequiredKeyword: map[string]int{"data": 1, "json": 1},
				Qualifiers:      []ArgCondition{{ArgIndex: 0, AnyOf: []string{"http://"}, Substring: true}},
				CWE:             "CWE-319",
				Rationale:       "the destination is written into the call as a plaintext URL",
			},
			{
				ID: "plaintext-outbound-body", Visibility: "thirdparty", Context: "plaintext-url",
				Symbol: "requests.put", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				RequiredKeyword: map[string]int{"data": 1, "json": 1},
				Qualifiers:      []ArgCondition{{ArgIndex: 0, AnyOf: []string{"http://"}, Substring: true}},
				CWE:             "CWE-319",
				Rationale:       "the destination is written into the call as a plaintext URL",
			},

			// The VALUE of a cookie. Whatever goes here is stored on a machine the
			// application does not control, sent on every request, and readable by
			// anything with access to the browser profile.
			{
				ID: "cookie-store", Visibility: "public", Context: "cookie-store",
				Method: "cookie", ReceiverIsEntryParam: 1, ArgIndex: []int{1},
				Qualifiers: []ArgCondition{{Keyword: "maxAge", Absent: true}},
				// No CWE here on purpose. Two policies use this channel and they are about
				// different weaknesses -- a credential STORED in a cookie, and a GUESSABLE
				// value used as one -- so the identity belongs to whichever judgement is
				// being made rather than to the destination.
				Rationale: "the second argument to cookie() is the value stored in the browser",
			},
			{
				ID: "cookie-store", Visibility: "public", Context: "cookie-store",
				Method: "set_cookie", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				Qualifiers: []ArgCondition{{Keyword: "max_age", Absent: true}},
				Rationale:  "the second argument to set_cookie() is the value stored in the browser",
			},
			{
				// The same value with an expiry on it, which is what makes the cookie
				// PERSISTENT: it survives the browser closing and sits on disk until the
				// date passes.
				ID: "persistent-cookie-store", Visibility: "public", Context: "cookie-persist",
				Method: "cookie", ReceiverIsEntryParam: 1, ArgIndex: []int{1},
				Qualifiers: []ArgCondition{{Keyword: "maxAge"}},
				Rationale:  "the cookie is given an expiry, so it is written to disk rather than held for the session",
			},
			{
				ID: "persistent-cookie-store", Visibility: "public", Context: "cookie-persist",
				Method: "set_cookie", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				Qualifiers: []ArgCondition{{Keyword: "max_age"}},
				Rationale:  "the cookie is given an expiry, so it is written to disk rather than held for the session",
			},

			// Where an operator can read it later. A log is not a secret store: it is
			// copied to aggregators, shipped to vendors, and kept long after the thing it
			// describes is gone.
			{
				// No CWE on the log channels: two policies use them and they are about
				// different weaknesses -- a credential written down, and a caller forging
				// log lines -- so the identity belongs to the judgement.
				ID: "log", Visibility: "operator", Symbol: "console.log", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				Context:   "log-line",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "console.info", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				Context:   "log-line",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "console.warn", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				Context:   "log-line",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "console.error", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				Context:   "log-line",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "console.debug", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				Context:   "log-line",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "logging.info", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				Context:   "log-line",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "logging.warning", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				Context:   "log-line",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "logging.error", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				Context:   "log-line",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "logging.debug", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				Context:   "log-line",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "logging.exception", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				Context:   "log-line",
				Rationale: "written to a log",
			},

			// `logging.getLogger(__name__)` is how Python logging is actually written, and
			// a channel that only knew the module-level functions was blind to nearly all
			// of it. The method name alone says nothing -- every object has an `error` --
			// so what makes it a log is that the receiver came out of getLogger.
			{
				ID: "log", Visibility: "operator", Method: "info", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				ReceiverFrom: []string{"getLogger", "getChild"},
				Context:      "log-line",
				Rationale:    "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Method: "warning", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				ReceiverFrom: []string{"getLogger", "getChild"},
				Context:      "log-line",
				Rationale:    "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Method: "warn", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				ReceiverFrom: []string{"getLogger", "getChild"},
				Context:      "log-line",
				Rationale:    "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Method: "error", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				ReceiverFrom: []string{"getLogger", "getChild"},
				Context:      "log-line",
				Rationale:    "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Method: "debug", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				ReceiverFrom: []string{"getLogger", "getChild"},
				Context:      "log-line",
				Rationale:    "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Method: "exception", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				ReceiverFrom: []string{"getLogger", "getChild"},
				Context:      "log-line",
				Rationale:    "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Method: "critical", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				ReceiverFrom: []string{"getLogger", "getChild"},
				Context:      "log-line",
				Rationale:    "written to a log",
			},

			// An allow-list checked with a PARTIAL match. `origin.startsWith("https://
			// example.com")` accepts `https://example.com.attacker.net`, and
			// `origin.endsWith("example.com")` accepts `https://notexample.com` -- the
			// list is right and the comparison is too generous, which is the harder half
			// to see because the allowed values look correct.
			//
			// The receiver is what is being checked, so the dataflow answers it: this
			// matches only where the string being matched is one the caller sent.
			{
				ID: "partial-match", Visibility: "internal", Context: "partial-match",
				Method: "startsWith", ReceiverIsEntryParam: -1,
				RequiresUntrustedReceiver: true,
				CWE:                       "CWE-183",
				Rationale:                 "a prefix match accepts anything that CONTINUES the allowed value",
			},
			{
				ID: "partial-match", Visibility: "internal", Context: "partial-match",
				Method: "endsWith", ReceiverIsEntryParam: -1,
				RequiresUntrustedReceiver: true,
				CWE:                       "CWE-183",
				Rationale:                 "a suffix match accepts anything that PRECEDES the allowed value",
			},
			{
				ID: "partial-match", Visibility: "internal", Context: "partial-match",
				Method: "includes", ReceiverIsEntryParam: -1,
				RequiresUntrustedReceiver: true,
				CWE:                       "CWE-183",
				Rationale:                 "a containment match accepts the allowed value anywhere in a longer one",
			},
			{
				ID: "partial-match", Visibility: "internal", Context: "partial-match",
				Method: "indexOf", ReceiverIsEntryParam: -1,
				RequiresUntrustedReceiver: true,
				CWE:                       "CWE-183",
				Rationale:                 "a containment match accepts the allowed value anywhere in a longer one",
			},
			{
				ID: "partial-match", Visibility: "internal", Context: "partial-match",
				Method: "startswith", ReceiverIsEntryParam: -1,
				RequiresUntrustedReceiver: true,
				CWE:                       "CWE-183",
				Rationale:                 "a prefix match accepts anything that CONTINUES the allowed value",
			},
			{
				ID: "partial-match", Visibility: "internal", Context: "partial-match",
				Method: "endswith", ReceiverIsEntryParam: -1,
				RequiresUntrustedReceiver: true,
				CWE:                       "CWE-183",
				Rationale:                 "a suffix match accepts anything that PRECEDES the allowed value",
			},

			// An LDAP filter is a small query language, and `*` in the wrong place turns
			// "this user with this password" into "any user".
			{
				ID: "ldap-filter", Visibility: "internal", Context: "ldap",
				Method: "search", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				RequiresExternalReceiver: true, RequiresComposition: true,
				CWE:       "CWE-90",
				Rationale: "the second argument to search() is the filter",
			},
			{
				ID: "ldap-filter", Visibility: "internal", Context: "ldap",
				// By METHOD, because the connection is always a bound object rather than
				// the module: `conn.search_s(...)`, never `ldap.search_s(...)`. The name
				// is distinctive enough to carry it.
				Method: "search_s", ReceiverIsEntryParam: -1, ArgIndex: []int{2},
				RequiresComposition: true,
				CWE:                 "CWE-90",
				Rationale:           "the third argument to search_s() is the filter",
			},
			{
				ID: "ldap-filter", Visibility: "internal", Context: "ldap",
				Method: "search_ext_s", ReceiverIsEntryParam: -1, ArgIndex: []int{2},
				RequiresComposition: true,
				CWE:                 "CWE-90",
				Rationale:           "the third argument to search_ext_s() is the filter",
			},

			// An XPath expression selects nodes, and one the caller writes selects
			// whichever nodes they like -- including the ones holding everybody else's
			// data.
			{
				ID: "xpath-expression", Visibility: "internal", Context: "xpath",
				Method: "xpath", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresComposition: true,
				CWE:                 "CWE-643",
				Rationale:           "the argument to xpath() is the expression",
			},
			{
				ID: "xpath-expression", Visibility: "internal", Context: "xpath",
				Symbol: "lxml.etree.XPath", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresComposition: true,
				CWE:                 "CWE-643",
				Rationale:           "XPath() compiles its argument as an expression",
			},
			{
				ID: "xpath-expression", Visibility: "internal", Context: "xpath",
				Method: "evaluate", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true, RequiresComposition: true,
				CWE:       "CWE-643",
				Rationale: "the first argument to evaluate() is the expression",
			},

			// A FORMAT STRING the caller supplied. `"Hello {}".format(name)` is safe: the
			// caller's data is an argument. `name.format(x)` is not, because Python's
			// format language walks attributes and indexes, and
			// `{0.__class__.__init__.__globals__}` reaches module globals and whatever
			// they hold.
			//
			// The two are the same method with the operands swapped, and the RECEIVER is
			// what tells them apart -- the same question the upload channel asks.
			{
				ID: "format-string", Visibility: "internal", Context: "format",
				Method: "format", ReceiverIsEntryParam: -1, RequiresUntrustedReceiver: true,
				Language:     "python",
				RequiresArgs: 1,
				CWE:          "CWE-134",
				Rationale:    "format() is called ON caller-supplied text, so the caller wrote the format",
			},
			{
				ID: "format-string", Visibility: "internal", Context: "format",
				Method: "format_map", ReceiverIsEntryParam: -1, RequiresUntrustedReceiver: true,
				Language:     "python",
				RequiresArgs: 1,
				CWE:          "CWE-134",
				Rationale:    "format_map() is called ON caller-supplied text, so the caller wrote the format",
			},

			// An XML parser that has been told to resolve entities will fetch and inline
			// whatever a document names, which is how a document becomes a file read on
			// the server. The option is the whole difference: libxmljs without `noent`
			// is the safe way to parse XML, and this says nothing about it.
			{
				ID: "xml-parser", Visibility: "internal", Context: "xml",
				Symbol: "libxmljs.parseXmlString", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "noent", AnyOf: []string{"true"}}},
				CWE:        "CWE-611",
				Rationale:  "parseXmlString() is asked to resolve entities with noent",
			},
			{
				ID: "xml-parser", Visibility: "internal", Context: "xml",
				Symbol: "libxmljs.parseXml", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "noent", AnyOf: []string{"true"}}},
				CWE:        "CWE-611",
				Rationale:  "parseXml() is asked to resolve entities with noent",
			},
			{
				// lxml's default parser resolves entities, so on this one the absence of
				// configuration IS the configuration.
				ID: "xml-parser", Visibility: "internal", Context: "xml",
				Symbol: "lxml.etree.fromstring", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				MaxArgs:    1,
				Qualifiers: []ArgCondition{{Keyword: "parser", Absent: true}},
				CWE:        "CWE-611",
				Rationale:  "lxml's default parser expands entities -- internally in every version, externally before lxml 5 -- and this call supplied no parser of its own",
			},
			{
				ID: "xml-parser", Visibility: "internal", Context: "xml",
				Symbol: "lxml.etree.XML", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				MaxArgs:    1,
				Qualifiers: []ArgCondition{{Keyword: "parser", Absent: true}},
				CWE:        "CWE-611",
				Rationale:  "lxml's default parser expands entities -- internally in every version, externally before lxml 5 -- and this call supplied no parser of its own",
			},
			{
				ID: "xml-parser", Visibility: "internal", Context: "xml",
				Symbol: "lxml.etree.parse", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				MaxArgs:    1,
				Qualifiers: []ArgCondition{{Keyword: "parser", Absent: true}},
				CWE:        "CWE-611",
				Rationale:  "lxml's default parser expands entities -- internally in every version, externally before lxml 5 -- and this call supplied no parser of its own",
			},

			// Where an uploaded file's BYTES come to rest. Separate from filesystem-path
			// because the danger is different and so is the fix: traversal is about
			// escaping a directory, and this is about what the file turns out to BE once
			// it is inside one. A stored `.php` under a served directory is a defect even
			// though nothing escaped anywhere.
			//
			// Keeping them apart is what lets `secure_filename` resolve one and not the
			// other. It strips separators, so no traversal survives it -- and it preserves
			// the extension exactly, which is the entire attack.
			{
				ID: "stored-upload-destination", Visibility: "internal", Context: "upload-type",
				Method: "save", ReceiverIsEntryParam: -1, RequiresUntrustedReceiver: true, ArgIndex: []int{0},
				RequiresUnprojectedReceiver: true,
				CWE:                         "CWE-434",
				Rationale:                   "writes an uploaded file to a destination the caller named",
			},
			{
				// express-fileupload moves the temporary file into place.
				ID: "stored-upload-destination", Visibility: "internal", Context: "upload-type",
				Method: "mv", ReceiverIsEntryParam: -1, RequiresUntrustedReceiver: true, ArgIndex: []int{0},
				RequiresUnprojectedReceiver: true,
				CWE:                         "CWE-434",
				Rationale:                   "moves an uploaded file to a destination the caller named",
			},
			// A template is a program. Every engine here exposes property access and
			// method calls to the template text, which is why server-side template
			// injection ends in code execution rather than in mangled markup -- Jinja
			// reaches the object graph through `__class__`, and Handlebars and Pug compile
			// to JavaScript. Distinct from the html context on purpose: escaping the five
			// characters that make markup does nothing to a template that is being
			// COMPILED rather than rendered into.
			{
				ID: "template-compiler", Visibility: "internal", Context: "template",
				Symbol: "flask.render_template_string", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1336",
				Rationale: "render_template_string() compiles its argument as a Jinja template",
			},
			{
				ID: "template-compiler", Visibility: "internal", Context: "template",
				Symbol: "jinja2.Template", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1336",
				Rationale: "Template() compiles its argument",
			},
			{
				ID: "template-compiler", Visibility: "internal", Context: "template",
				Symbol: "jinja2.Environment.from_string", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1336",
				Rationale: "from_string() compiles its argument as a template",
			},
			{
				ID: "template-compiler", Visibility: "internal", Context: "template",
				Symbol: "handlebars.compile", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1336",
				Rationale: "compile() turns template text into a function",
			},
			{
				ID: "template-compiler", Visibility: "internal", Context: "template",
				Symbol: "handlebars.default.compile", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1336",
				Rationale: "compile() turns template text into a function",
			},
			{
				ID: "template-compiler", Visibility: "internal", Context: "template",
				Symbol: "pug.compile", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1336",
				Rationale: "compile() turns template text into a function",
			},
			{
				ID: "template-compiler", Visibility: "internal", Context: "template",
				Symbol: "pug.render", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1336",
				Rationale: "render() compiles its first argument as a template",
			},
			{
				ID: "template-compiler", Visibility: "internal", Context: "template",
				Symbol: "ejs.render", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1336",
				Rationale: "render() compiles its first argument as a template",
			},
			{
				ID: "template-compiler", Visibility: "internal", Context: "template",
				Symbol: "nunjucks.renderString", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1336",
				Rationale: "renderString() compiles its first argument as a template",
			},
			{
				ID: "template-compiler", Visibility: "internal", Context: "template",
				Symbol: "lodash.template", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-1336",
				Rationale: "template() compiles its argument into a function",
			},
			// The synchronous variants live in `fs` and the promise-returning ones in
			// `fs/promises`, and neither module has the other's. `fs/promises.readFileSync`
			// was described here and could never match anything, which is a rule that
			// looks like coverage and is not -- found by auditing the symbol list against
			// the libraries rather than by anything failing.
			// The whole request body handed to a view as its locals.
			//
			// A template engine's render options are not only data: Handlebars and
			// express-handlebars read `layout` out of them and load the file it names, so
			// a caller who sends `{"layout": "../../etc/passwd"}` chooses which file the
			// server reads. What makes it decidable is that the body arrived WHOLE --
			// `res.render("page", { name: req.body.name })` names one field and cannot
			// carry an option nobody asked for, and the frontends already record which of
			// the two happened.
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Method: "render", ReceiverIsEntryParam: 1, ArgIndex: []int{1},
				RequiresUnenclosed: true,
				CWE:                "CWE-22",
				Rationale:          "the render options are read for a layout or a view name, and this call hands over everything the caller sent",
			},

			// An archive the caller supplied, unpacked. Every entry in it names its own
			// destination, so an entry called `../../etc/cron.d/x` writes there -- the
			// path traversal is inside the file rather than in the call, which is why the
			// question here is what the archive IS rather than what the path says.
			//
			// The receiver is the evidence and the dataflow already answers it: `zip_ref`
			// came out of ZipFile(uploaded), so asking whether the thing being extracted
			// is caller-supplied costs a map lookup.
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Method: "extractAllToAsync", ReceiverIsEntryParam: -1,
				RequiresUntrustedReceiver: true,
				CWE:                       "CWE-22",
				Rationale:                 "every entry in the archive names where it goes, and this archive came from the caller",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Method: "extractAllTo", ReceiverIsEntryParam: -1,
				RequiresUntrustedReceiver: true,
				CWE:                       "CWE-22",
				Rationale:                 "every entry in the archive names where it goes, and this archive came from the caller",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Method: "extractEntryTo", ReceiverIsEntryParam: -1,
				RequiresUntrustedReceiver: true,
				CWE:                       "CWE-22",
				Rationale:                 "the entry being extracted names where it goes, and this archive came from the caller",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Method: "extractall", ReceiverIsEntryParam: -1,
				RequiresUntrustedReceiver: true,
				CWE:                       "CWE-22",
				Rationale:                 "every entry in an archive names where it goes, and this archive came from the caller",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Method: "extract", ReceiverIsEntryParam: -1,
				RequiresUntrustedReceiver: true,
				CWE:                       "CWE-22",
				Rationale:                 "the entry being extracted names where it goes, and this archive came from the caller",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs.readFile", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs/promises.readFile", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs.readFileSync", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs.writeFile", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs/promises.writeFile", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs.writeFileSync", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs.appendFile", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs/promises.appendFile", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs.appendFileSync", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs.createReadStream", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs.createWriteStream", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs.unlink", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs/promises.unlink", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs.unlinkSync", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs.rm", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs/promises.rm", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs.rmSync", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs.readdir", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs/promises.readdir", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "fs.readdirSync", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Method: "sendFile", ReceiverIsEntryParam: 1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file sent to the caller",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "builtins.open", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"file": 0},
				CWE:             "CWE-22",
				Rationale:       "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "os.remove", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"path": 0},
				CWE:             "CWE-22",
				Rationale:       "the first argument names the file this deletes",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "flask.send_file", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"path_or_file": 0},
				CWE:             "CWE-22",
				Rationale:       "the first argument names the file sent to the caller",
			},
			{
				ID: "shell-command", Visibility: "internal", Context: "shell",
				Symbol: "child_process.exec", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-78",
				Rationale: "exec() runs its first argument through /bin/sh",
			},
			{
				ID: "shell-command", Visibility: "internal", Context: "shell",
				Symbol: "child_process.execSync", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-78",
				Rationale: "execSync() runs its first argument through /bin/sh",
			},
			{
				// execFile does not use a shell, so only the executable path is
				// interpreted. The argument array is not a shell context.
				ID: "process-launch", Visibility: "internal", Context: "exec-path",
				Symbol: "child_process.execFile", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-73",
				Rationale: "execFile() does not use a shell; only the file path is interpreted",
			},
			{
				ID: "http-response-body", Visibility: "public", Context: "http-response",
				Method: "json", ReceiverIsEntryParam: 1, ArgIndex: []int{0},
				Rationale: "returned to whoever called the endpoint",
			},
			{
				ID: "http-response-body", Visibility: "public", Context: "http-response",
				Method: "send", ReceiverIsEntryParam: 1, ArgIndex: []int{0},
				Rationale: "returned to whoever called the endpoint",
			},
			// A response body the browser parses as markup. Distinct from the
			// http-response channel above, which is about who can SEE a value: this is
			// about what the destination DOES with it. The same `res.send` is both, and
			// the two judgements are different — internal error detail reaching it is a
			// disclosure, caller-supplied markup reaching it is script execution.
			//
			// No policy was written for this. `untrusted-to-interpreter` already denies
			// the html context, so describing the channel was the whole change: a rule
			// authored for operating-system shells covers cross-site scripting because
			// what it actually says is that a caller must not choose what an interpreter
			// executes, and a browser is an interpreter (ADR-012).
			{
				ID: "html-response", Visibility: "public", Context: "html",
				Method: "send", ReceiverIsEntryParam: 1, ArgIndex: []int{0},
				CWE:       "CWE-79",
				Rationale: "the response body is parsed as markup by the browser",
			},
			{
				ID: "html-response", Visibility: "public", Context: "html",
				Method: "write", ReceiverIsEntryParam: 1, ArgIndex: []int{0},
				CWE:       "CWE-79",
				Rationale: "the response body is parsed as markup by the browser",
			},
			{
				ID: "html-response", Visibility: "public", Context: "html",
				Method: "end", ReceiverIsEntryParam: 1, ArgIndex: []int{0},
				CWE:       "CWE-79",
				Rationale: "the response body is parsed as markup by the browser",
			},
			// Operations that act on ONE record chosen by their argument. The property
			// that matters is record selection, not which ORM is in use.
			// Sequelize, Mongoose and TypeORM name the same operation differently, and the
			// vocabulary here had been Prisma's alone. A documented privilege escalation
			// in a deliberately vulnerable application went unreported for exactly that
			// reason: `db.User.find({where: {id: req.body.id}})` lets the caller choose
			// whose password gets reset, and the engine had no word for `find`.
			//
			// `Array.prototype.find` shares the name and is not this. It is excluded by
			// the receiver requirement rather than by a special case, because an array is
			// one of the language's own containers and no question about who owns an
			// element of one has an answer.
			{
				ID: "record-selector", Visibility: "internal", Context: "record-selector",
				Method: "find", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true,
				Rationale:                "selects records by the criteria it is given",
			},
			{
				ID: "record-selector", Visibility: "internal", Context: "record-selector",
				Method: "findOne", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true,
				Rationale:                "selects a single record by the criteria it is given",
			},
			{
				ID: "record-selector", Visibility: "internal", Context: "record-selector",
				Method: "findAll", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true,
				Rationale:                "selects records by the criteria it is given",
			},
			{
				ID: "record-selector", Visibility: "internal", Context: "record-selector",
				Method: "findByPk", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true,
				Rationale:                "selects a single record by the identifier it is given",
			},
			{
				ID: "record-selector", Visibility: "internal", Context: "record-selector",
				Method: "findById", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true,
				Rationale:                "selects a single record by the identifier it is given",
			},
			{
				ID: "record-selector", Visibility: "internal", Context: "record-selector",
				Method: "findOneAndUpdate", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true,
				Rationale:                "modifies a single record chosen by the criteria it is given",
			},
			{
				ID: "record-selector", Visibility: "internal", Context: "record-selector",
				Method: "findOneAndDelete", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true,
				Rationale:                "removes a single record chosen by the criteria it is given",
			},
			{
				ID: "record-selector", Visibility: "internal", Context: "record-selector",
				Method: "updateOne", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true,
				Rationale:                "modifies a single record chosen by the criteria it is given",
			},
			{
				ID: "record-selector", Visibility: "internal", Context: "record-selector",
				Method: "deleteOne", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true,
				Rationale:                "removes a single record chosen by the criteria it is given",
			},
			{
				ID: "record-selector", Visibility: "internal", Context: "record-selector",
				Method: "destroy", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true,
				Rationale:                "removes records chosen by the criteria it is given",
			},
			{
				ID: "record-selector", Visibility: "internal", Context: "record-selector",
				Method: "findUnique", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true,
				Rationale:                "selects a single record by the identifier it is given",
			},
			{
				ID: "record-selector", Visibility: "internal", Context: "record-selector",
				Method: "findFirst", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true,
				Rationale:                "selects a single record by the identifier it is given",
			},
			{
				ID: "record-selector", Visibility: "internal", Context: "record-selector",
				Method: "delete", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true,
				Rationale:                "removes a single record by the identifier it is given",
			},
			{
				ID: "record-selector", Visibility: "internal", Context: "record-selector",
				Method: "update", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiresExternalReceiver: true,
				ReceiverNotFrom:          []string{"createHash", "createHmac", "createCipheriv", "createDecipheriv"},
				// A selector is a value the caller HANDED OVER; a message is one the
				// program BUILT. `update` is the one record operation whose Python
				// spelling takes the new field values rather than the criteria --
				// Django's `qs.filter(...).update(field=value)` chose the record in the
				// `filter` above and this call writes into it -- and a keyword argument
				// arrives at index 0 exactly like a positional one, so nothing else
				// separates the two readings. Composition does: healthchecks builds
				// `f"Delivery failed ({diagnostic})"` out of a bounced email and writes
				// it to `last_error`, and reading that as "the caller chose which record"
				// is the same mistake an earlier adjudication recorded against superset.
				// The stated cost is a composite key built by concatenation, which is
				// not reported.
				RequiresWholeValue: true,
				Rationale:          "modifies a single record by the identifier it is given",
			},
			// SQL execution. Described as an OPERATION rather than as a library: what
			// matters is that this argument is read as SQL, and that is equally true of
			// mysql, pg, sequelize, knex and a raw cursor.
			//
			// ArgIndex is what makes a parameterized query safe, and it is worth being
			// explicit about why. `execute(sql, params)` interprets its FIRST argument
			// and treats the second as data, so a channel that names argument 0 already
			// says everything there is to say: untrusted data in the params never
			// reaches an interpreter, and no exception, allowlist or "is it
			// parameterized" heuristic is needed to express that. The distinction the
			// whole defect turns on is a property of the channel, not a special case.
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "query", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "the first argument is executed as SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "execute", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "the first argument is executed as SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "executemany", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "the first argument is executed as SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "raw", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "raw() hands its argument to the database as SQL",
			},
			// pg-promise, whose whole API is the row count it expects rather than the word
			// "query": `db.one(sql)`, `db.many(sql)`, `db.none(sql)`. Four of the five SQL
			// injections in one vulnerable application were invisible because of this, and
			// the method list is what a scanner has instead of knowing the library.
			//
			// These names are generic enough that a name alone would be reckless -- `one`,
			// `any` and `result` are ordinary words. What makes them safe here is the
			// requirement every SQL channel already carries: the value must have been BUILT
			// into a statement. Passing a value along whole is passing data.
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "none", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "none() hands its first argument to the database as SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "one", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "one() hands its first argument to the database as SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "many", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "many() hands its first argument to the database as SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "any", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "any() hands its first argument to the database as SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "oneOrNone", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "oneOrNone() hands its first argument to the database as SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "manyOrNone", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "manyOrNone() hands its first argument to the database as SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "result", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "result() hands its first argument to the database as SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "multiResult", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "multiResult() hands its first argument to the database as SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "multi", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "multi() hands its first argument to the database as SQL",
			},
			{
				// Named Unsafe by its own authors, for this reason.
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "$queryRawUnsafe", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "$queryRawUnsafe() interpolates its argument into SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "$executeRawUnsafe", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				ComposedContains:    sqlVerbs,
				Rationale:           "$executeRawUnsafe() interpolates its argument into SQL",
			},
			{
				// A language's own evaluator is an interpreter like any other, and the
				// existing policy already forbids untrusted input reaching one. Adding
				// the channel is a data change; no policy and no engine code moved
				// (ADR-004). The weakness differs from a shell's, so the CHANNEL names
				// it rather than the policy (ADR-012).
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Symbol: "eval", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-95",
				Rationale: "eval() executes its argument as program source",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Symbol: "Function", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-95",
				Rationale: "the Function constructor compiles its argument as program source",
			},
			// An expression evaluator is an interpreter. `mathjs` looks like arithmetic
			// and is not: its expression language reaches the host through function
			// definitions and property access, which is why its own advisories are
			// remote code execution. A recall audit found one in a vulnerable
			// application and the symbol was simply absent.
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Symbol: "mathjs.eval", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-95",
				Rationale: "eval evaluates its argument as an expression, and the expression language reaches the host",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Symbol: "mathjs.evaluate", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-95",
				Rationale: "evaluate evaluates its argument as an expression, and the expression language reaches the host",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Symbol: "mathjs.default.eval", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-95",
				Rationale: "eval evaluates its argument as an expression, and the expression language reaches the host",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Symbol: "mathjs.default.evaluate", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-95",
				Rationale: "evaluate evaluates its argument as an expression, and the expression language reaches the host",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Symbol: "math.eval", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-95",
				Rationale: "eval evaluates its argument as an expression, and the expression language reaches the host",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Symbol: "math.evaluate", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-95",
				Rationale: "evaluate evaluates its argument as an expression, and the expression language reaches the host",
			},
			{
				// MongoDB's `$where` takes a JavaScript EXPRESSION and evaluates it on the
				// server, so caller data in one is caller data being executed -- the same
				// judgement as eval, at a different interpreter.
				//
				// Named by the option rather than by the callee: `find`, `findOne`,
				// `updateMany` and every wrapper over them accept it, and what makes it
				// dangerous is the key, not which method carried it.
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "find", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "findOne", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "findOneAndUpdate", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "updateMany", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "updateOne", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "update", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "deleteMany", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "count", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "countDocuments", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "deleteOne", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "findOneAndDelete", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "replaceOne", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "findOneAndReplace", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "aggregate", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				// distinct(field, query): the FIELD is argument 0 and the filter is
				// argument 1, which is the one place in this family the index moves.
				Method: "distinct", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				// A sandbox that is not one. `vm` isolates the global object and nothing
				// else: code inside it reaches back out through constructors and
				// prototypes, which the module's own documentation says outright.
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Symbol: "vm.runInNewContext", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-95",
				Rationale: "runInNewContext() compiles and runs its argument as program source",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Symbol: "vm.runInThisContext", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-95",
				Rationale: "runInThisContext() runs its argument in this process's own global scope",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Symbol: "vm.compileFunction", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-95",
				Rationale: "compileFunction() compiles its argument as a function body",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Symbol: "vm.Script", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-95",
				Rationale: "a Script is compiled from its argument as program source",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Symbol: "builtins.eval", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-95",
				Rationale: "eval() executes its argument as program source",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Symbol: "builtins.exec", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-95",
				Rationale: "exec() executes its argument as program source",
			},
			// Python's usual way of running a command. `subprocess.run(["ls", x])` passes
			// a list and is safe; `subprocess.run("ls " + x, shell=True)` builds a string
			// and is not. The composition requirement separates them without the model
			// needing to read the shell= keyword: a list of arguments is assembled, a
			// command line is composed.
			{
				ID: "shell-command", Visibility: "internal", Context: "shell",
				Symbol: "subprocess.run", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"args": 0},
				CWE:             "CWE-78", RequiresComposition: true,
				Rationale: "a composed string passed here is run by the shell",
			},
			{
				ID: "shell-command", Visibility: "internal", Context: "shell",
				Symbol: "subprocess.call", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"args": 0},
				CWE:             "CWE-78", RequiresComposition: true,
				Rationale: "a composed string passed here is run by the shell",
			},
			{
				ID: "shell-command", Visibility: "internal", Context: "shell",
				Symbol: "subprocess.check_output", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"args": 0},
				CWE:             "CWE-78", RequiresComposition: true,
				Rationale: "a composed string passed here is run by the shell",
			},
			{
				ID: "shell-command", Visibility: "internal", Context: "shell",
				Symbol: "subprocess.Popen", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"args": 0},
				CWE:             "CWE-78", RequiresComposition: true,
				Rationale: "a composed string passed here is run by the shell",
			},
			{
				ID: "process-arguments", Visibility: "internal", Context: "argv",
				Symbol: "subprocess.run", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"args": 0},
				CWE:             "CWE-88", RequiresEnclosure: true,
				Rationale: "each list element is interpreted independently as a process argument",
			},
			{
				ID: "process-arguments", Visibility: "internal", Context: "argv",
				Symbol: "subprocess.call", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"args": 0},
				CWE:             "CWE-88", RequiresEnclosure: true,
				Rationale: "each list element is interpreted independently as a process argument",
			},
			{
				ID: "process-arguments", Visibility: "internal", Context: "argv",
				Symbol: "subprocess.check_output", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"args": 0},
				CWE:             "CWE-88", RequiresEnclosure: true,
				Rationale: "each list element is interpreted independently as a process argument",
			},
			{
				ID: "process-arguments", Visibility: "internal", Context: "argv",
				Symbol: "subprocess.check_call", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"args": 0},
				CWE:             "CWE-88", RequiresEnclosure: true,
				Rationale: "each list element is interpreted independently as a process argument",
			},
			{
				ID: "process-arguments", Visibility: "internal", Context: "argv",
				Symbol: "subprocess.Popen", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				RequiredKeyword: map[string]int{"args": 0},
				CWE:             "CWE-88", RequiresEnclosure: true,
				Rationale: "each list element is interpreted independently as a process argument",
			},
			{
				ID: "process-arguments", Visibility: "internal", Context: "argv",
				Symbol: "os.execv", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				CWE: "CWE-88", RequiresEnclosure: true,
				Rationale: "each list element is interpreted independently as a process argument",
			},
			{
				ID: "process-arguments", Visibility: "internal", Context: "argv",
				Symbol: "os.execve", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				CWE: "CWE-88", RequiresEnclosure: true,
				Rationale: "each list element is interpreted independently as a process argument",
			},
			{
				ID: "process-arguments", Visibility: "internal", Context: "argv",
				Symbol: "os.execvp", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				CWE: "CWE-88", RequiresEnclosure: true,
				Rationale: "each list element is interpreted independently as a process argument",
			},
			{
				ID: "process-arguments", Visibility: "internal", Context: "argv",
				Symbol: "os.execvpe", ReceiverIsEntryParam: -1, ArgIndex: []int{1},
				CWE: "CWE-88", RequiresEnclosure: true,
				Rationale: "each list element is interpreted independently as a process argument",
			},
			{
				ID: "shell-command", Visibility: "internal", Context: "shell",
				Symbol: "os.system", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-78",
				Rationale: "os.system() passes its argument to the shell",
			},
			{
				ID: "http-response-body", Visibility: "public", Context: "http-response",
				Symbol: "flask.jsonify", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Rationale: "returned to whoever called the endpoint",
			},

			// A value written into a VIEW. The frontend has already read the template and
			// decided which of these the engine escapes, which is the only question the
			// template language answers and the one the handler cannot.
			//
			// Two channels rather than one, because escaping settles a different question
			// from visibility. `<%= password %>` is escaped and still a password on a
			// page; `<%- comment %>` is unescaped and is script execution. The first is
			// public and not markup; the second is both.
			{
				ID: "html-response", Visibility: "public", Context: "html",
				Symbol: "<template>.unescaped", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-79",
				Rationale: "the template writes this value into the page without escaping it",
			},
			{
				ID: "template-output", Visibility: "public", Context: "html-escaped",
				Symbol: "<template>.escaped", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Rationale: "the template writes this value into the page, escaped",
			},
			{
				// Inside a `<script>` element, which is neither markup nor a JavaScript
				// string. The HTML parser ends the element at the first `</script`
				// whatever the JavaScript around it says, and it does NOT decode entities
				// in there -- so escaping for a JavaScript string leaves the sequence that
				// ends the element intact, while HTML-escaping happens to remove it.
				//
				// A separate context because that is the whole of the difference: the
				// encoders that answer it are not the encoders that answer a JavaScript
				// string, and an engine that files both under one name cannot say which
				// one was reached for.
				ID: "html-response", Visibility: "public", Context: "script",
				Symbol: "<template>.script", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-79",
				Rationale: "the value is written into a <script> element unescaped, where the element ends at the first </script whatever the surrounding JavaScript says",
			},
			{
				ID: "url-target", Visibility: "public", Context: "url-target",
				Symbol: "<template>.url-target", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-79",
				Rationale: "HTML escaping does not constrain the scheme of a URL-valued attribute",
			},
			{
				ID: "url-part", Visibility: "public", Context: "url-part",
				Symbol: "<template>.url-part", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-116",
				Rationale: "the value is interpreted as path or query syntax inside a URL-valued attribute",
			},
			// Turning the framework's escaping OFF, by name. Angular escapes everything
			// it renders and offers exactly one way out, spelled so that nobody can use
			// it by accident -- which makes it the clearest possible statement that
			// whatever reaches it will be written into the page as markup.
			{
				ID: "html-response", Visibility: "public", Context: "html",
				Method: "bypassSecurityTrustHtml", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-79",
				Rationale: "bypassSecurityTrustHtml tells the framework to stop escaping this value",
			},
			{
				ID: "html-response", Visibility: "public", Context: "html",
				Method: "bypassSecurityTrustScript", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-79",
				Rationale: "bypassSecurityTrustScript tells the framework to stop escaping this value",
			},
			{
				ID: "html-response", Visibility: "public", Context: "html",
				Method: "bypassSecurityTrustResourceUrl", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-79",
				Rationale: "bypassSecurityTrustResourceUrl tells the framework to stop escaping this value",
			},
			{
				ID: "html-response", Visibility: "public", Context: "html",
				Method: "bypassSecurityTrustUrl", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-79",
				Rationale: "bypassSecurityTrustUrl tells the framework to stop escaping this value",
			},
			{
				ID: "html-response", Visibility: "public", Context: "html",
				Method: "bypassSecurityTrustStyle", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-79",
				Rationale: "bypassSecurityTrustStyle tells the framework to stop escaping this value",
			},
			// Added as a DESCRIPTION of a channel, not as a rule for a defect.
			// Every policy that denies a class reaching "thirdparty" now covers
			// outbound HTTP without being touched.
			//
			// Mutually exclusive with the plaintext channel above, and deliberately so:
			// the two describe the same argument of the same call, and a policy that asks
			// about VISIBILITY rather than context matches both -- which reported every
			// outbound leak twice. The scheme decides which one speaks, the same way an
			// expiry decides which cookie channel speaks.
			{
				ID: "outbound-http", Visibility: "thirdparty",
				Symbol: "axios.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1},
				Qualifiers: []ArgCondition{{ArgIndex: 0, Substring: true, NoneOf: []string{"http://"}}},
				Rationale:  "leaves this trust boundary for a system we do not control",
			},
			{
				ID: "outbound-http", Visibility: "thirdparty",
				Symbol: "axios.put", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1},
				Qualifiers: []ArgCondition{{ArgIndex: 0, Substring: true, NoneOf: []string{"http://"}}},
				Rationale:  "leaves this trust boundary for a system we do not control",
			},
			{
				ID: "outbound-http", Visibility: "thirdparty",
				Symbol: "axios.patch", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1},
				Qualifiers: []ArgCondition{{ArgIndex: 0, Substring: true, NoneOf: []string{"http://"}}},
				Rationale:  "leaves this trust boundary for a system we do not control",
			},
			{
				ID: "outbound-http", Visibility: "thirdparty",
				Symbol: "requests.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1},
				RequiredKeyword: map[string]int{"data": 1, "json": 1, "url": 0},
				Qualifiers:      []ArgCondition{{ArgIndex: 0, Substring: true, NoneOf: []string{"http://"}}},
				Rationale:       "leaves this trust boundary for a system we do not control",
			},
			{
				ID: "outbound-http", Visibility: "thirdparty",
				Symbol: "requests.put", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1},
				RequiredKeyword: map[string]int{"data": 1, "json": 1, "url": 0},
				Qualifiers:      []ArgCondition{{ArgIndex: 0, Substring: true, NoneOf: []string{"http://"}}},
				Rationale:       "leaves this trust boundary for a system we do not control",
			},
			{
				ID: "outbound-http", Visibility: "thirdparty",
				Symbol: "requests.patch", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1},
				RequiredKeyword: map[string]int{"data": 1, "json": 1, "url": 0},
				Qualifiers:      []ArgCondition{{ArgIndex: 0, Substring: true, NoneOf: []string{"http://"}}},
				Rationale:       "leaves this trust boundary for a system we do not control",
			},
			{
				ID: "outbound-http", Visibility: "thirdparty",
				Symbol: "httpx.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1},
				RequiredKeyword: map[string]int{"content": 1, "data": 1, "files": 1, "json": 1, "url": 0},
				Qualifiers:      []ArgCondition{{ArgIndex: 0, Substring: true, NoneOf: []string{"http://"}}},
				Rationale:       "leaves this trust boundary for a system we do not control",
			},
		},

		// WHAT IS FORBIDDEN. Judgements about class-and-channel pairings. Each covers
		// every instance of the pairing, including channels added later.
		CallShapes: builtinCallShapes(),
		Decisions:  builtinDecisions(),
		Stores:     builtinStores(),
		Guards:     builtinGuards(),
		Scopes:     builtinScopes(),
		// Not a judgement at all: where the program's values are KEPT, so that a lookup
		// answers with what was stored rather than with what it was asked for.
		Persistence: builtinPersistence(),
		// Not a rule and not a defect: the vocabulary the value-shape rules decide a
		// literal's ROLE in, so that a key this program hands to somebody else's service
		// to say which client it is stops being reported as this program's secret.
		ClientRole: builtinClientRole(),

		Policies: []Policy{
			{
				ID:            "untrusted-to-interpreter",
				Class:         "untrusted-input",
				DeniedContext: []string{"shell", "argv", "exec-path", "sql", "html", "script", "code", "template", "ldap", "xpath", "url-target", "url-part"},
				Reason:        "a caller must not be able to choose what an interpreter executes",
				Finding:       "Untrusted input reaches an interpreter",
				CWE:           "CWE-78",
			},
			{
				ID:              "process-argument-to-argv",
				Class:           "process-argument-input",
				RequiredContext: []string{"argv"},
				Reason:          "data supplied to a process-launch lifecycle hook must not be interpreted as an option",
				Finding:         "Untrusted input reaches a process argument",
				CWE:             "CWE-88",
			},
			{
				// The same judgement one request later. A stored value reaching an
				// interpreter is the classic stored injection -- stored XSS is this
				// policy at an HTML channel -- and the reason it needs its own policy
				// rather than a second class on the first one is that the DENIED SET is
				// narrower. A first-order caller value in a log line is worth saying; a
				// stored one is a row the application wrote about itself, and the noise
				// of saying so everywhere would swamp the four findings this exists for.
				// Only the destinations that INTERPRET what they are given are claimed.
				ID:            "stored-to-interpreter",
				Class:         "second-order-input",
				DeniedContext: []string{"shell", "argv", "exec-path", "sql", "html", "script", "code", "template", "ldap", "xpath"},
				Reason:        "a value one caller stored is read back by another request and interpreted there, so the store is the delivery mechanism rather than the request that arrives with it",
				Finding:       "Stored input reaches an interpreter",
				CWE:           "CWE-78",
			},
			{
				// The interpreter set and nothing else, exactly as the stored-input
				// policy above draws it and for the same reason: a destination that
				// INTERPRETS its input is dangerous whoever wrote the input, and every
				// other destination turns on a question about the upstream that the
				// source does not answer. An upstream response written to a log is a log
				// of what the upstream said; an upstream response sent onward to another
				// service is an integration. Neither is a weakness, and claiming them
				// would bury the ones that are.
				ID:    "upstream-response-to-interpreter",
				Class: "upstream-response",
				// The interpreter set plus the XML parser, and the parser is here because
				// the measurement put it here. Widened experimentally to every context
				// the first-order class denies, this policy added nine findings to pdfjs
				// -- a `console.warn`, two build scripts downloading Mozilla's
				// translations, and vendored WASM glue -- one to linkwarden, and eight to
				// searxng. The eight are `lxml.etree.fromstring(resp.content)` in eight
				// engine modules, and the engine ALREADY asserts that exact pairing for a
				// document a caller sent: lxml's default parser expands entities, the
				// call supplied no parser of its own, and a parser does not care who
				// wrote the document it was handed. The other ten turned on whose service
				// it was, which is the question this class declines to answer.
				//
				// `ldap` is deliberately absent, and the measurement is why. The LDAP
				// filter channel matches the METHOD NAME `search` on a receiver it
				// requires to be external -- and a frontend that cannot type receivers
				// leaves that unanswerable, which is correctly not the same as "not
				// builtin", so the channel matches at reduced confidence. In Python that
				// makes `re.search(pattern, url)` an LDAP filter: yt-dlp
				// `extractor/common.py`:2686 was the one wrong finding this family
				// produced, and it was wrong about the SINK rather than about the source.
				// Pairing a second class with a channel that already misreads a stdlib
				// call would multiply a known imprecision, so an upstream response
				// reaching a real LDAP filter is a stated miss until that channel can
				// tell `re` from a directory connection.
				DeniedContext: []string{"shell", "argv", "exec-path", "sql", "html", "code", "template", "xpath", "xml"},
				Reason:        "the bytes were chosen by whoever runs the service that answered, and this destination interprets what it is given rather than merely carrying it",
				Finding:       "A response from another service reaches an interpreter",
				CWE:           "CWE-78",
			},
			{
				ID:                 "unowned-record-access",
				Class:              "untrusted-input",
				RequiredContext:    []string{"record-selector"},
				RequiresRelationTo: "actor-identity",
				ExemptedBy:         "establishesIdentity",
				// Deciding whether a check GATES the operation, rather than merely
				// preceding it, is a control-flow question.
				Requires: Requirements{ControlFlow: true},
				Reason:   "the caller chooses which record is operated on, and the handler never consults who the caller is",
				Finding:  "Missing ownership check",
				CWE:      "CWE-639",
			},
			{
				// The other direction of the regex weakness, and the common one. A caller
				// who writes the PATTERN is rare; a caller who feeds a long string to a
				// pattern that backtracks is how a process actually gets stopped.
				ID:            "untrusted-to-catastrophic-regex",
				Class:         "untrusted-input",
				DeniedContext: []string{"regex-subject"},
				Reason:        "the pattern can be made to backtrack exponentially, so a long string a caller chooses stops the process without touching it",
				Finding:       "Untrusted input is matched against a pattern that can be made to churn",
				CWE:           "CWE-1333",
			},
			{
				ID:            "untrusted-to-glob",
				Class:         "untrusted-input",
				DeniedContext: []string{"glob"},
				Reason:        "the argument is interpreted as a wildcard pattern, so a caller who writes one chooses which files the program walks rather than which file it opens",
				Finding:       "Untrusted input is interpreted as a file pattern",
				CWE:           "CWE-155",
			},
			{
				// Composed INTO the document, which is what separates this from parsing a
				// document a caller sent. The second is ordinary and is judged by what the
				// parser is configured to do; this is the caller writing XML syntax.
				ID:    "untrusted-into-xml",
				Class: "untrusted-input",
				// A context of its own, and it has to be. The parser channels already use
				// "xml" for the OTHER question -- a document the caller sent, judged by
				// what the parser was asked to resolve -- and sharing the name paired this
				// policy with those channels and reported one call twice.
				DeniedContext: []string{"xml-composed"},
				Reason:        "the caller's text is built into the document rather than carried by it, so a caller who writes a tag gets a tag",
				Finding:       "Untrusted input is built into an XML document",
				CWE:           "CWE-91",
			},
			{
				ID:            "untrusted-to-regex",
				Class:         "untrusted-input",
				DeniedContext: []string{"regex"},
				Reason:        "a caller who writes the pattern can choose one that takes exponential time, which stops the process without touching it",
				Finding:       "Untrusted input is compiled as a regular expression",
				CWE:           "CWE-1333",
			},
			{
				ID:            "untrusted-to-redirect",
				Class:         "untrusted-input",
				DeniedContext: []string{"redirect"},
				Reason:        "a caller must not be able to choose where this application sends a browser, because the application's own name is what makes the destination look trustworthy",
				Finding:       "Untrusted input chooses a redirect destination",
				CWE:           "CWE-601",
			},
			{
				// Not injection and not deserialization: nothing is interpreted and nothing
				// is reconstructed. The application simply never said which fields it
				// meant to accept, so the caller decides. The remedy is an allowlist of
				// fields, which is why this is its own judgement.
				ID:            "untrusted-to-record-fields",
				Class:         "untrusted-input",
				DeniedContext: []string{"record-fields"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "an application must choose which fields a caller may write, because handing over the whole object hands over the ones nobody meant to expose",
				Finding:       "Caller's object written to a record whole",
				CWE:           "CWE-915",
			},
			{
				// The interpreter is a spreadsheet on somebody else's machine, which is
				// why this channel is thirdparty rather than internal.
				ID:            "untrusted-to-spreadsheet",
				Class:         "untrusted-input",
				DeniedContext: []string{"csv"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "a spreadsheet runs a cell that begins with a formula character, so whoever opens the export runs whatever the caller put in it",
				Finding:       "Untrusted input written to a spreadsheet cell",
				CWE:           "CWE-1236",
			},
			{
				// Nothing is executed and nothing is stored: the caller writes the FORMAT,
				// and Python's format language is expressive enough to walk from any
				// object it is given to module globals.
				ID:            "untrusted-as-format-string",
				Class:         "untrusted-input",
				DeniedContext: []string{"format"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "a caller must not supply the format itself, because a format is a small language that can read whatever the objects it is handed can reach",
				Finding:       "Caller supplies the format string",
				CWE:           "CWE-134",
			},
			{
				// An external entity reference is not deserialization and not injection: the
				// document names a resource and the parser goes and gets it. Its own
				// policy, because its own remedy -- turn entity resolution off.
				ID:            "untrusted-to-xml-parser",
				Class:         "untrusted-input",
				DeniedContext: []string{"xml"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "a parser told to resolve entities will fetch whatever the document names, so a caller who supplies the document chooses what the server reads",
				Finding:       "Untrusted XML parsed with entity resolution enabled",
				CWE:           "CWE-611",
			},
			{
				ID:            "untrusted-to-deserializer",
				Class:         "untrusted-input",
				DeniedContext: []string{"deserialize"},
				Reason:        "a deserializer that reconstructs arbitrary objects lets a caller choose what is constructed, and therefore what runs",
				Finding:       "Untrusted input reaches an object deserializer",
				CWE:           "CWE-502",
			},
			{
				ID:            "untrusted-to-outbound-destination",
				Class:         "untrusted-input",
				DeniedContext: []string{"url"},
				Reason:        "a caller must not be able to choose which machine the application makes a request to from inside the network",
				Finding:       "Untrusted input chooses a request destination",
				CWE:           "CWE-918",
			},
			{
				// The weakness is not that the file lands in the wrong PLACE -- that is
				// CWE-22 next door -- but that the caller decided what KIND of file the
				// server now holds. An allowlist of extensions resolves it; making the
				// path safe does not.
				ID:            "untrusted-to-stored-file-type",
				Class:         "untrusted-input",
				DeniedContext: []string{"upload-type"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "a caller must not be able to choose the type of file the application stores",
				Finding:       "Untrusted input chooses a stored file's type",
				CWE:           "CWE-434",
			},
			{
				ID:            "untrusted-to-filesystem-path",
				Class:         "untrusted-input",
				DeniedContext: []string{"path"},
				Reason:        "a caller must not be able to choose which file the application opens",
				Finding:       "Untrusted input chooses a file path",
				CWE:           "CWE-22",
			},
			{
				// A query string is the least private part of a request: it is in the
				// access log at both ends, in the Referer header of whatever the page
				// loads next, and in browser history. A credential does not belong there
				// even over TLS.
				ID:            "credential-in-url",
				Class:         "caller-credential",
				DeniedContext: []string{"url-query"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "a credential in a URL is written to access logs at both ends, sent onward in the Referer header, and kept in browser history",
				Finding:       "Credential placed in a URL",
				CWE:           "CWE-598",
			},
			{
				// A carriage return and a newline end a header and begin whatever comes
				// next, so a caller who can put them in a header value writes headers of
				// their own -- or a body.
				ID:            "untrusted-to-header",
				Class:         "untrusted-input",
				DeniedContext: []string{"header"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "a caller who can put a line break in a header value ends the header and begins one of their own",
				Finding:       "Untrusted input reaches a response header",
				CWE:           "CWE-93",
			},
			{
				// A caller choosing how much memory to reserve is a caller choosing when
				// the process dies. Nothing is interpreted and nothing leaks: the request
				// simply asks for more than there is.
				ID:            "untrusted-allocation-size",
				Class:         "untrusted-input",
				DeniedContext: []string{"allocation"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "a caller who chooses how much memory to reserve chooses when the process runs out of it",
				Finding:       "Untrusted input sizes an allocation",
				CWE:           "CWE-789",
			},
			{
				// Where the interpreter looks for modules is a security decision, and a
				// caller who can steer it decides what the next import runs.
				ID:            "untrusted-search-path",
				Class:         "untrusted-input",
				DeniedContext: []string{"search-path"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "a caller who can add to the module search path decides where the next import comes from, and an import runs whatever it finds",
				Finding:       "Untrusted input added to the module search path",
				CWE:           "CWE-426",
			},
			{
				// Anyone on the path reads it: the network, a proxy, whatever terminates
				// the connection. Distinct from writing it to a log, and distinct from the
				// destination being untrusted -- the destination here is one the
				// application chose and wrote down, and the problem is the scheme.
				ID:            "credential-in-cleartext",
				Class:         "caller-credential",
				DeniedContext: []string{"plaintext-url"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "a credential sent over plain HTTP is readable by anyone on the path between here and the destination",
				Finding:       "Credential sent over an unencrypted connection",
				CWE:           "CWE-319",
			},
			{
				// A cookie value is something a caller must not be able to guess: guessing
				// one is being that user. This is the sink that turns a weak generator
				// from a fact into a weakness, and it is why the generator alone is not
				// reported -- the same call is a retry delay somewhere else in the same
				// file.
				ID:            "predictable-secret",
				Class:         "predictable-value",
				DeniedContext: []string{"cookie-store", "cookie-persist"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "a value a caller must not be able to guess cannot come from a generator built for speed, because its output is reproducible from a few samples",
				Finding:       "Guessable value used where unpredictability is required",
				CWE:           "CWE-338",
			},
			{
				// A seed decides every number that follows it. Seeded from the clock, the
				// sequence is reproducible by anyone who knows roughly when the process
				// started, which for a server is anyone who has ever made a request to it.
				ID:            "predictable-seed",
				Class:         "observable-value",
				DeniedContext: []string{"prng-seed"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "a seed anybody can recompute makes every number that follows it recomputable, and the clock is the most guessable seed there is",
				Finding:       "Random number generator seeded from an observable value",
				CWE:           "CWE-337",
			},
			{
				// A generator that is perfect and was asked for too little. Four random
				// bytes are four billion candidates, which is a weekend for anyone who
				// wants the session.
				ID:            "short-secret",
				Class:         "short-random-value",
				DeniedContext: []string{"cookie-store", "cookie-persist"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "a value under 128 bits can be searched, and the generator being a good one does not help when there is not enough of it",
				Finding:       "Too few random bits where unpredictability is required",
				CWE:           "CWE-331",
			},
			{
				// The judgement the algorithm's name could never make. A digest is only
				// as good as what is asked of it: standing in for the thing it was
				// computed from is the one job that needs collision resistance, and a
				// verification call is the program saying in its own code that this is
				// the job.
				//
				// The mirror image is the whole point and is not an omission: a digest
				// that goes out in a URL, into a filename or into a cache key is not
				// being trusted by this program, whatever the remote end does with it.
				// Twenty-six of yt-dlp's twenty-seven are exactly that -- a signature the
				// site's protocol demands -- and this policy is silent about every one.
				ID:            "weak-digest-verified",
				Class:         "weak-digest",
				DeniedContext: []string{"proof"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "the value being verified is a digest from an algorithm anybody can find collisions in, so a second input passes this check as readily as the right one and the check establishes nothing",
				Finding:       "Broken digest trusted as proof",
				CWE:           "CWE-328",
			},
			{
				// Written where operators, log shippers and whoever else reads the logs
				// can see it. Distinct from a credential in a log by what it costs: a
				// password gets rotated and an identity number does not.
				ID:                  "personal-information-logged",
				Class:               "personal-information",
				DeniedContext:       []string{"log-line"},
				RequiresUnprojected: true,
				Requires:            Requirements{Interprocedural: true},
				Reason:              "a fact like this cannot be reissued after it leaks, and a log is copied to more places than anyone tracks",
				Finding:             "Personal information written to a log",
				CWE:                 "CWE-359",
			},
			{
				// Handed to somebody else's service.
				ID:                  "personal-information-sent",
				Class:               "personal-information",
				DeniedVisibility:    []string{"thirdparty"},
				RequiresUnprojected: true,
				Requires:            Requirements{Interprocedural: true},
				Reason:              "a fact like this cannot be reissued after it leaks, and where it goes after leaving this process is not this process's decision any more",
				Finding:             "Personal information sent outside this system",
				CWE:                 "CWE-359",
			},
			{
				// An origin or a referrer checked against an allow-list by prefix, suffix
				// or containment. The list is right and the comparison is too generous:
				// a prefix match accepts anything that continues the allowed value and a
				// suffix match accepts anything that precedes it, so
				// `https://example.com.attacker.net` and `https://notexample.com` both
				// pass a check that looks correct.
				ID:            "permissive-origin-match",
				Class:         "referer",
				DeniedContext: []string{"partial-match"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "a prefix or suffix match on an origin accepts every value that extends the allowed one, so an attacker registers a name that continues it and passes a check nobody reads as broken",
				Finding:       "Origin checked against an allow-list by partial match",
				CWE:           "CWE-183",
			},
			{
				// The clock reaching somewhere unguessability is the whole point. A token
				// built from the current time is a token an attacker can enumerate by
				// trying the seconds around the moment it was issued.
				ID:            "observable-secret",
				Class:         "observable-value",
				DeniedContext: []string{"cookie-store", "cookie-persist"},
				Requires:      Requirements{Interprocedural: true},
				Reason:        "a value built from the clock is reproducible by anyone who knows roughly when it was issued, and a value a caller must not be able to guess cannot be reproducible at all",
				Finding:       "Value derived from observable state used where unpredictability is required",
				CWE:           "CWE-341",
			},
			{
				// On disk it outlives the process, the request and usually the incident:
				// it is in the backup, in the image, and in whatever the log shipper picks
				// up next.
				ID:                  "credential-stored-cleartext",
				Class:               "caller-credential",
				DeniedContext:       []string{"storage"},
				RequiresUnprojected: true,
				Requires:            Requirements{Interprocedural: true},
				Reason:              "a credential written to a file outlives the request that carried it and ends up in backups and images nobody thinks of as holding secrets",
				Finding:             "Credential written to a file in the clear",
				CWE:                 "CWE-312",
			},
			{
				// A cache outlives the request that filled it and is usually shared --
				// another process, another host, a service somebody else runs.
				ID:                  "credential-cached",
				Class:               "caller-credential",
				DeniedContext:       []string{"cache"},
				RequiresUnprojected: true,
				Requires:            Requirements{Interprocedural: true},
				Reason:              "a cache outlives the request that filled it and is usually shared, so a credential put there is a credential in every process that can read it",
				Finding:             "Credential written to a cache",
				CWE:                 "CWE-524",
			},
			{
				// A hash with no salt is a pure function of the password, so one
				// precomputed table works against every account at once.
				ID:                  "credential-unsalted-hash",
				Class:               "caller-credential",
				DeniedContext:       []string{"unsalted-digest"},
				RequiresUnprojected: true,
				Requires:            Requirements{Interprocedural: true},
				Reason:              "a hash that takes no salt turns the password into a value that depends on nothing else, so one precomputed table works against every account that chose the same password",
				Finding:             "Password hashed without a salt",
				CWE:                 "CWE-759",
			},
			{
				// Encoding is not hiding. base64 turns straight back into what went in,
				// and anybody who has the encoded form has the password.
				ID:                  "credential-encoded",
				Class:               "caller-credential",
				DeniedContext:       []string{"reversible"},
				RequiresUnprojected: true,
				Requires:            Requirements{Interprocedural: true},
				Reason:              "base64 is an encoding rather than a transformation, so whoever holds the result holds the password",
				Finding:             "Password merely encoded",
				CWE:                 "CWE-261",
			},
			{
				// Encryption is not hashing. A stored password must not be recoverable
				// AT ALL, and encryption is recoverable by design -- that is what it is
				// for.
				ID:                  "credential-encrypted",
				Class:               "caller-credential",
				DeniedContext:       []string{"recoverable"},
				RequiresUnprojected: true,
				Requires:            Requirements{Interprocedural: true},
				Reason:              "encryption is reversible by design, so a password kept that way is recoverable by anyone who reaches the key",
				Finding:             "Password kept in a recoverable form",
				CWE:                 "CWE-257",
			},
			{
				// A cookie is storage on a machine the application does not control. A
				// credential put there is sent on every request and readable by anything
				// with access to the browser profile, and an expiry makes it survive the
				// browser closing.
				ID:                  "credential-in-cookie",
				Class:               "caller-credential",
				DeniedContext:       []string{"cookie-store"},
				RequiresUnprojected: true,
				Requires:            Requirements{Interprocedural: true},
				Reason:              "a credential stored in a cookie sits on a machine the application does not control and is sent on every request to it",
				Finding:             "Credential stored in a cookie",
				CWE:                 "CWE-315",
			},
			{
				// The same value with an EXPIRY, which is a different weakness: it
				// survives the browser closing and sits on disk until the date passes.
				ID:                  "credential-in-persistent-cookie",
				Class:               "caller-credential",
				DeniedContext:       []string{"cookie-persist"},
				RequiresUnprojected: true,
				Requires:            Requirements{Interprocedural: true},
				Reason:              "a credential in a cookie with an expiry outlives the session, sitting on disk until the date passes",
				Finding:             "Credential stored in a persistent cookie",
				CWE:                 "CWE-539",
			},
			{
				// Echoed back to whoever sent it. Narrower than it sounds, and precisely
				// because the class is a credential the CALLER SENT: a login endpoint
				// returning a freshly issued token is returning something it generated,
				// which is the entire point of a login endpoint and is not this. This is
				// `res.json(req.body)` on a form that had a password in it.
				ID:    "credential-echoed",
				Class: "caller-credential",
				// The response BODY by context rather than by visibility. A cookie is
				// public too, and putting a credential in one is a different judgement
				// with a different remedy -- naming visibility here made every cookie
				// finding report twice under two numbers.
				DeniedContext:       []string{"http-response", "html", "script"},
				RequiresUnprojected: true,
				Requires:            Requirements{Interprocedural: true},
				Reason:              "a credential the caller sent must not come back in the response, where it reaches proxies, caches and browser history that had no reason to hold it",
				Finding:             "Caller's credential echoed back",
				CWE:                 "CWE-201",
			},
			{
				// A log is a record somebody reads later to work out what happened, and a
				// caller who can put a line break in it writes entries of their own --
				// with any timestamp, level and actor they like. Composition is required:
				// a value logged whole is a field, and a value built INTO a line is a line.
				ID:                  "untrusted-to-log-line",
				Class:               "untrusted-input",
				DeniedContext:       []string{"log-line"},
				RequiresComposition: true,
				Requires:            Requirements{Interprocedural: true},
				Reason:              "a caller who can put a line break into a log entry writes entries of their own, with whatever timestamp, level and actor they choose",
				Finding:             "Untrusted input composed into a log line",
				CWE:                 "CWE-117",
			},
			{
				// A password in a log is a password in every aggregator, vendor and backup
				// the log reaches, long after the request it belonged to is gone. Its own
				// judgement because its own remedy: do not write it down.
				ID:    "credential-recorded",
				Class: "caller-credential",
				// Logs only. A credential reaching a response or a third party is a real
				// judgement and a DIFFERENT one, with its own remedy and its own identity,
				// and folding them in here would put the wrong number on them.
				DeniedVisibility: []string{"operator"},
				Requires:         Requirements{Interprocedural: true},
				// A credential is the VALUE, not a field of something you fetched with
				// it. etherpad takes a token out of the URL, looks a record up with it,
				// and returns one non-secret field of that record -- and the comment
				// above the line says so. The token never leaves; something it addressed
				// does.
				RequiresUnprojected: true,
				Reason:              "a credential written anywhere durable outlives the request it belonged to and reaches everyone who can read what it was written to",
				Finding:             "Caller's credential recorded",
				CWE:                 "CWE-532",
			},
			{
				// Not the same judgement as an error message reaching a caller, though
				// they land in the same place: an error describes one failure, and the
				// environment is the whole set of secrets the process holds. Handing over
				// a single variable on purpose is ordinary and is not this.
				ID:                  "environment-outward",
				Class:               "system-information",
				DeniedVisibility:    []string{"public", "thirdparty"},
				RequiresUnprojected: true,
				Requires:            Requirements{Interprocedural: true},
				Reason:              "the environment holds every secret the process was started with, so handing it out whole hands out all of them",
				Finding:             "Process environment exposed",
				CWE:                 "CWE-497",
			},
			{
				// Not subsumed by CWE-79 even though it sits beneath it, and the reason
				// is the SOURCE. This engine classifies failure detail separately from
				// caller input precisely so it can tell them apart, and an error message
				// written into a page unescaped is the shape that carries the caller's own
				// bad input back to them -- which is how the message becomes script.
				//
				// It is a second reading of a line the disclosure policy also reads, and
				// both are true: the message describes the system to people outside it AND
				// it is written into markup without escaping. Different fixes, so both are
				// reported (ADR-016).
				ID:                    "error-detail-into-markup",
				Class:                 "internal-error",
				DeniedContext:         []string{"html", "script", "template"},
				ClassNamesTheWeakness: true,
				Reason:                "an error message is where a program repeats back what it was given, so writing one into a page unescaped hands the caller a way to put script there",
				Finding:               "Error message written into a page unescaped",
				CWE:                   "CWE-81",
			},
			{
				ID:                    "internal-detail-outward",
				Class:                 "internal-error",
				DeniedVisibility:      []string{"public", "thirdparty"},
				ClassNamesTheWeakness: true,
				// Who reads the message is what this judgement is about. Nine of
				// linkwarden's twenty-one findings were this rule; eight were adjudicated
				// true and not one was worth reporting, because every one of them hands a
				// library error string to a caller who already owns the account. The same
				// rule found two of the batch's four worth-reporting findings in
				// uptime-kuma, where the endpoints answer anybody. Same rule, same
				// weakness, different audience -- and until now the same rank.
				AudienceDecides: true,
				Reason:          "internal failure detail describes the system to people outside it",
				Finding:         "Sensitive information exposure",
				CWE:             "CWE-209",
			},
		},

		// The calls that resolve a relative reference against a base. Every one of them
		// re-parses its reference argument, which is what makes a `/` prefix stop
		// anchoring the host: `urljoin("http://127.0.0.1:8080", "//evil.example/x")` is
		// `http://evil.example/x`, and an application that writes `"/" + path` has handed
		// the caller the second slash.
		//
		// Measured on archivebox: `/opencode/<path>` builds `f"/{path}"`, joins it onto
		// the configured origin, and passes the result to `requests.request`. The channel
		// asked whether the caller supplied a whole destination, read the literal `/` in
		// front, and correctly answered no -- for a concatenation. This is not one.
		Resolvers: []ResolverRule{
			{
				Symbol: "urllib.parse.urljoin", RefArg: 1,
				Note: "resolves argument 1 as a URL reference against argument 0, so a reference beginning // replaces the base's host",
			},
			{
				Symbol: "urljoin", RefArg: 1,
				Note: "resolves argument 1 as a URL reference against argument 0, so a reference beginning // replaces the base's host",
			},
			{
				// The web platform's spelling of the same operation, in the same
				// argument order reversed: `new URL(reference, base)`.
				Symbol: "URL", RefArg: 0,
				Note: "resolves argument 0 as a URL reference against the base in argument 1, so a reference beginning // replaces the base's host",
			},
			{
				Symbol: "url.resolve", RefArg: 1,
				Note: "resolves argument 1 as a URL reference against argument 0, so a reference beginning // replaces the base's host",
			},
		},

		Sanitizers: []SanitizerRule{
			{
				// A payload whose SIGNATURE was checked against a shared secret is not
				// something the caller wrote. `constructEvent` recomputes an HMAC over the
				// raw body with the endpoint secret and THROWS when it does not match, so
				// everything past that line came from Stripe rather than from whoever made
				// the request.
				//
				// Measured: linkwarden logs `eventType` from the constructed event, and
				// the engine called it log injection. The unsigned body leaves through the
				// verification-failure response several lines earlier and never reaches
				// the log at all. Two of eight false positives in that repository were
				// this exact shape, at two different payment providers.
				//
				// Scoped to untrusted-input and nothing else, for the reason the number
				// conversions above are scoped: verification establishes WHO WROTE a
				// value, and says nothing about whether the value is predictable or
				// whether there is a secret inside it. A verified webhook carrying an API
				// key is still carrying an API key.
				Symbol:   "stripe.webhooks.constructEvent",
				Contexts: []string{AnyContext},
				Classes:  []string{"untrusted-input"},
				Note:     "throws unless an HMAC over the raw body matches the endpoint secret, so the result was written by the sender and not by the caller",
			},
			{
				// The same judgement, from the library a great many projects use for
				// webhooks they did not write themselves. `verify` throws on a bad
				// signature; there is no return value to check and no way past it.
				Symbol:   "svix.Webhook.verify",
				Contexts: []string{AnyContext},
				Classes:  []string{"untrusted-input"},
				Note:     "throws unless the signature matches the endpoint secret",
			},
			{
				Symbol:   "path.basename",
				Contexts: []string{"path"},
				Note:     "reduces a path to its final segment, so no traversal survives it",
			},
			{
				Symbol:   "os.path.basename",
				Contexts: []string{"path"},
				Note:     "reduces a path to its final segment, so no traversal survives it",
			},
			{
				// Deliberately "path" and nothing else. It strips directory separators and
				// non-ASCII, which ends traversal -- and it leaves `.php` exactly as it
				// found it. A transform only neutralizes the context it addresses, and
				// this one does not address type at all.
				Symbol:   "werkzeug.utils.secure_filename",
				Contexts: []string{"path"},
				Note:     "reduces a filename to a safe single segment; preserves the extension",
			},
			{
				Symbol:   "secure_filename",
				Contexts: []string{"path"},
				Note:     "reduces a filename to a safe single segment; preserves the extension",
			},
			{
				// Flask's own confined variant: it resolves against a directory and
				// refuses anything that escapes it.
				Symbol:   "flask.send_from_directory",
				Contexts: []string{"path"},
				Note:     "resolves within a fixed directory and rejects paths escaping it",
			},
			{
				// Flask resolves an endpoint NAME to a URL. Everything the caller supplies
				// becomes a query parameter of a destination the application chose.
				Symbol:             "flask.url_for",
				Contexts:           []string{"redirect", "url", "path"},
				Note:               "resolves a named endpoint to a URL; caller data becomes query parameters of a destination the application chose",
				RequiresLiteralArg: arg(0),
			},
			{
				Symbol:             "url_for",
				Contexts:           []string{"redirect", "url", "path"},
				Note:               "resolves a named endpoint to a URL; caller data becomes query parameters of a destination the application chose",
				RequiresLiteralArg: arg(0),
			},
			{
				Symbol:   "glob.escape",
				Contexts: []string{"glob"},
				Note:     "escapes the wildcard characters, so what is left names one file",
			},
			{
				Symbol:   "xml.sax.saxutils.escape",
				Contexts: []string{"xml-composed"},
				Note:     "replaces the characters that would start a tag or an entity",
			},
			{
				Symbol:   "saxutils.escape",
				Contexts: []string{"xml-composed"},
				Note:     "replaces the characters that would start a tag or an entity",
			},
			{
				// A NUMBER cannot carry syntax. Not a line break, not a quote, not a path
				// separator, not a tag -- so numeric coercion clears every text context
				// there is, which is why it is marked for all of them rather than listed
				// against each.
				//
				// ghost logs `Blocking for ${seconds} seconds` where seconds came from
				// parseInt, and that read as log forging: the caller cannot put a newline
				// in a number.
				Symbol:   "parseInt",
				Contexts: []string{AnyContext},
				// Scoped to the class the argument is actually about. A number cannot
				// carry syntax, so it neutralizes anything a caller might have written --
				// and it does nothing whatever about PREDICTABILITY. `int(time.time())`
				// is still the clock, and while these cleared every class the finding for
				// a token built from the clock disappeared the moment the Python spelling
				// started matching at all.
				Classes: []string{"untrusted-input"},
				Note:    "produces a number, which cannot carry syntax",
			},
			{
				Symbol:   "parseFloat",
				Contexts: []string{AnyContext},
				// Scoped to the class the argument is actually about. A number cannot
				// carry syntax, so it neutralizes anything a caller might have written --
				// and it does nothing whatever about PREDICTABILITY. `int(time.time())`
				// is still the clock, and while these cleared every class the finding for
				// a token built from the clock disappeared the moment the Python spelling
				// started matching at all.
				Classes: []string{"untrusted-input"},
				Note:    "produces a number, which cannot carry syntax",
			},
			{
				Symbol:   "Number",
				Contexts: []string{AnyContext},
				// Scoped to the class the argument is actually about. A number cannot
				// carry syntax, so it neutralizes anything a caller might have written --
				// and it does nothing whatever about PREDICTABILITY. `int(time.time())`
				// is still the clock, and while these cleared every class the finding for
				// a token built from the clock disappeared the moment the Python spelling
				// started matching at all.
				Classes: []string{"untrusted-input"},
				Note:    "produces a number, which cannot carry syntax",
			},
			{
				Symbol:   "builtins.int",
				Contexts: []string{AnyContext},
				// Scoped to the class the argument is actually about. A number cannot
				// carry syntax, so it neutralizes anything a caller might have written --
				// and it does nothing whatever about PREDICTABILITY. `int(time.time())`
				// is still the clock, and while these cleared every class the finding for
				// a token built from the clock disappeared the moment the Python spelling
				// started matching at all.
				Classes: []string{"untrusted-input"},
				Note:    "produces a number, which cannot carry syntax",
			},
			{
				Symbol:   "builtins.float",
				Contexts: []string{AnyContext},
				// Scoped to the class the argument is actually about. A number cannot
				// carry syntax, so it neutralizes anything a caller might have written --
				// and it does nothing whatever about PREDICTABILITY. `int(time.time())`
				// is still the clock, and while these cleared every class the finding for
				// a token built from the clock disappeared the moment the Python spelling
				// started matching at all.
				Classes: []string{"untrusted-input"},
				Note:    "produces a number, which cannot carry syntax",
			},
			{
				// One-way by construction: the output is a verifier, and nothing that
				// reads it can recover what was hashed. This ends the credential rather
				// than making it safe for somewhere in particular.
				Symbol:   "bcrypt.hash",
				Contexts: []string{AnyContext},
				Note:     "a password hash is a verifier and not the password",
			},
			{
				Symbol:   "bcrypt.hashSync",
				Contexts: []string{AnyContext},
				Note:     "a password hash is a verifier and not the password",
			},
			{
				Symbol:   "argon2.hash",
				Contexts: []string{AnyContext},
				Note:     "a password hash is a verifier and not the password",
			},
			{
				Symbol:   "crypto.pbkdf2",
				Contexts: []string{AnyContext},
				Note:     "a derived key is not the password it was derived from",
			},
			{
				Symbol:   "crypto.pbkdf2Sync",
				Contexts: []string{AnyContext},
				Note:     "a derived key is not the password it was derived from",
			},
			{
				Symbol:   "hashlib.pbkdf2_hmac",
				Contexts: []string{AnyContext},
				Note:     "a derived key is not the password it was derived from",
			},
			{
				Symbol:   "hashlib.md5",
				Contexts: []string{AnyContext},
				Note:     "a digest is not what was digested, and a hex digest cannot carry syntax",
			},
			{
				Symbol:   "hashlib.sha1",
				Contexts: []string{AnyContext},
				Note:     "a digest is not what was digested, and a hex digest cannot carry syntax",
			},
			{
				Symbol:   "hashlib.sha224",
				Contexts: []string{AnyContext},
				Note:     "a digest is not what was digested, and a hex digest cannot carry syntax",
			},
			{
				Symbol:   "hashlib.sha256",
				Contexts: []string{AnyContext},
				Note:     "a digest is not what was digested, and a hex digest cannot carry syntax",
			},
			{
				Symbol:   "hashlib.sha384",
				Contexts: []string{AnyContext},
				Note:     "a digest is not what was digested, and a hex digest cannot carry syntax",
			},
			{
				Symbol:   "hashlib.sha512",
				Contexts: []string{AnyContext},
				Note:     "a digest is not what was digested, and a hex digest cannot carry syntax",
			},
			{
				Symbol:   "hashlib.sha3_256",
				Contexts: []string{AnyContext},
				Note:     "a digest is not what was digested, and a hex digest cannot carry syntax",
			},
			{
				Symbol:   "hashlib.sha3_512",
				Contexts: []string{AnyContext},
				Note:     "a digest is not what was digested, and a hex digest cannot carry syntax",
			},
			{
				Symbol:   "hashlib.new",
				Contexts: []string{AnyContext},
				Note:     "a digest is not what was digested, and a hex digest cannot carry syntax",
			},
			// VERIFYING. A token whose signature was checked carries claims the server
			// itself issued, so selecting a record by one is the caller reaching their OWN
			// record -- which is what an ownership check is for, not a violation of one.
			//
			// Scoped to that question and no further. The claims are still values somebody
			// chose at registration, so a name out of a verified token interpolated into a
			// SQL statement is still injection, and this says nothing about it.
			{
				Symbol:   "jsonwebtoken.verify",
				Classes:  []string{"untrusted-input"},
				Contexts: []string{"record-selector"},
				Note:     "the signature was checked, so these claims are the ones this server issued",
			},
			{
				Symbol:   "jose.jwtVerify",
				Classes:  []string{"untrusted-input"},
				Contexts: []string{"record-selector"},
				Note:     "the signature was checked, so these claims are the ones this server issued",
			},
			{
				Symbol:   "jwt.decode",
				Classes:  []string{"untrusted-input"},
				Contexts: []string{"record-selector"},
				Note:     "PyJWT verifies by default, so these claims are the ones this server issued",
			},

			// SIGNING. A signed token cannot be forged even when every field in it is
			// public, so it ends the question "could a caller have guessed this" -- and
			// only that question. A JWT payload is base64 rather than encrypted, so a
			// secret put inside one is still a secret in the open, and the credential
			// classifications are deliberately not listed here.
			{
				Symbol:   "jwt.encode",
				Classes:  []string{"predictable-value", "observable-value", "short-random-value"},
				Contexts: []string{AnyContext},
				Note:     "the signature is what makes a token unguessable, whatever the payload was built from",
			},
			{
				Symbol:   "jsonwebtoken.sign",
				Classes:  []string{"predictable-value", "observable-value", "short-random-value"},
				Contexts: []string{AnyContext},
				Note:     "the signature is what makes a token unguessable, whatever the payload was built from",
			},
			{
				Symbol:   "jose.jwt.encode",
				Classes:  []string{"predictable-value", "observable-value", "short-random-value"},
				Contexts: []string{AnyContext},
				Note:     "the signature is what makes a token unguessable, whatever the payload was built from",
			},
			{
				Symbol:   "itsdangerous.URLSafeTimedSerializer.dumps",
				Classes:  []string{"predictable-value", "observable-value", "short-random-value"},
				Contexts: []string{AnyContext},
				Note:     "the signature is what makes a token unguessable, whatever the payload was built from",
			},
			{
				Symbol:   "itsdangerous.TimestampSigner.sign",
				Classes:  []string{"predictable-value", "observable-value", "short-random-value"},
				Contexts: []string{AnyContext},
				Note:     "the signature is what makes a token unguessable, whatever the payload was built from",
			},

			{
				// Node's digest is a method on an object, so the identity comes from
				// what built the object rather than from the name.
				//
				// Except the digest's OWN class: this call is what produces a digest, so
				// it cannot also be what ends the question of where that digest goes.
				Method:      "digest",
				AfterSymbol: []string{"createHash", "createHmac"},
				Contexts:    []string{AnyContext},
				Except:      []string{"weak-digest", "computed-secret"},
				Note:        "a digest is not what was digested, and a hex digest cannot carry syntax",
			},
			{
				Method:      "hexdigest",
				AfterSymbol: []string{"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "new"},
				Contexts:    []string{AnyContext},
				Except:      []string{"weak-digest", "computed-secret"},
				Note:        "a digest is not what was digested, and a hex digest cannot carry syntax",
			},
			{
				Symbol:   "werkzeug.security.generate_password_hash",
				Contexts: []string{AnyContext},
				Note:     "a password hash is a verifier and not the password",
			},
			{
				// The LDAP filter escaper, under the several names the libraries give it.
				// redash calls it and then interpolates the result into a filter
				// template, which is the correct shape and read as a finding without
				// this.
				Symbol:   "escape_filter_chars",
				Contexts: []string{"ldap"},
				Note:     "escapes the characters an LDAP filter treats as syntax",
			},
			{
				Symbol:   "ldap.filter.escape_filter_chars",
				Contexts: []string{"ldap"},
				Note:     "escapes the characters an LDAP filter treats as syntax",
			},
			{
				Symbol:   "ldap3.utils.conv.escape_filter_chars",
				Contexts: []string{"ldap"},
				Note:     "escapes the characters an LDAP filter treats as syntax",
			},
			{
				Symbol:   "ldap.filter.filter_format",
				Contexts: []string{"ldap"},
				Note:     "builds a filter with its arguments escaped",
			},
			{
				// The package whose entire job is producing a well-formed
				// Content-Disposition: it encodes the filename rather than interpolating
				// it, which is the correct way to put a caller's filename in a header and
				// is read as a finding without this.
				Symbol:   "content-disposition",
				Contexts: []string{"header"},
				Note:     "encodes a filename into a well-formed header value",
			},
			{
				Symbol:   "content-disposition.default",
				Contexts: []string{"header"},
				Note:     "encodes a filename into a well-formed header value",
			},
			{
				// The regex escaper. novu builds `^${escapeRegExp(email)}$` and compiles
				// it, which is the correct way to search for a literal string and read as
				// catastrophic backtracking without this.
				Symbol:   "escapeRegExp",
				Contexts: []string{"regex"},
				Note:     "escapes the characters a pattern treats as syntax",
			},
			{
				Symbol:   "lodash.escapeRegExp",
				Contexts: []string{"regex"},
				Note:     "escapes the characters a pattern treats as syntax",
			},
			{
				Symbol:   "re.escape",
				Contexts: []string{"regex"},
				Note:     "escapes the characters a pattern treats as syntax",
			},
			{
				Symbol:   "escape-html",
				Contexts: []string{"html", "script"},
				Note:     "escapes the five characters that make markup",
			},
			{
				// The same package reached through a default import. A module's identity
				// is not the name a file happened to bind it to.
				Symbol:   "escape-html.default",
				Contexts: []string{"html", "script"},
				Note:     "escapes the five characters that make markup",
			},
			{
				Symbol:   "he.escape",
				Contexts: []string{"html", "script"},
				Note:     "HTML-encodes its input",
			},
			{
				Symbol:   "he.encode",
				Contexts: []string{"html", "script"},
				Note:     "HTML-encodes its input",
			},
			{
				Symbol:   "dompurify.sanitize",
				Contexts: []string{"html"},
				Note:     "removes scripting constructs from markup",
			},
			{
				// Python's side of the same judgement. `escape()` returns Markup, which
				// is precisely a value the template engine has been told is already safe
				// -- so `{{ escape(x) | safe }}` is correct code and the rule has to know
				// it, or it reports the remedy.
				Symbol:   "markupsafe.escape",
				Contexts: []string{"html", "script"},
				Note:     "escapes the five characters that make markup and returns Markup",
			},
			{
				Symbol:   "flask.escape",
				Contexts: []string{"html", "script"},
				Note:     "escapes the five characters that make markup and returns Markup",
			},
			{
				Symbol:   "html.escape",
				Contexts: []string{"html", "script"},
				Note:     "HTML-escapes its input",
			},
			{
				Symbol:   "cgi.escape",
				Contexts: []string{"html", "script"},
				Note:     "HTML-escapes its input",
			},
			{
				Symbol:   "bleach.clean",
				Contexts: []string{"html"},
				Note:     "removes scripting constructs from markup",
			},

			// Encoders for a JavaScript STRING, which is not the same place as a script
			// ELEMENT. Each of these escapes the quote and the backslash that would end
			// the string literal, and none of them escapes `<` or `/` -- so a value that
			// went through one still carries `</script>`, and the HTML parser ends the
			// element there whatever the JavaScript around it says.
			//
			// Declared even though nothing in this model asks about a JavaScript string
			// yet, because the point is what they DO NOT clear: without the rule the
			// engine cannot say that an encoder was reached for and answered the wrong
			// question, and "considered and insufficient" is a different report from
			// "nothing was tried" (ADR-006).
			{
				Symbol:   "json.dumps",
				Contexts: []string{"javascript-string"},
				Note:     "escapes what would end a JavaScript string, and not what ends a <script> element",
			},
			{
				Symbol:   "JSON.stringify",
				Contexts: []string{"javascript-string"},
				Note:     "escapes what would end a JavaScript string, and not what ends a <script> element",
			},

			{
				Symbol:   "shell-quote.quote",
				Contexts: []string{"shell"},
				Note:     "quotes arguments for shell interpretation",
			},
			{
				Symbol:   "encodeURIComponent",
				Contexts: []string{"url", "url-target", "url-part"},
				Note:     "percent-encodes for a URL context only; it neutralizes nothing for any other context",
			},
			{
				// Tornado appends the second argument as an encoded query mapping. It does
				// not constrain the first argument, which remains capable of choosing a
				// host or scheme; the input-argument condition is the security boundary.
				Symbol:           "tornado.httputil.url_concat",
				Contexts:         []string{"url-target", "url-part"},
				Note:             "percent-encodes the query mapping and appends it to the separately supplied URL",
				RequiresInputArg: arg(1),
			},
		},

		Callbacks: []CallbackRule{
			// The one OUTWARD rule, and the only construct in either language that needs
			// one. Everything a promise ever carries was handed to `resolve` inside the
			// executor -- often from a callback several frames deeper, because the whole
			// reason to write `new Promise` by hand is to bridge a callback API -- and the
			// executor's own return value is discarded. Without this the value computed
			// inside the executor reaches nothing at all, and the helper that computes it
			// reads as a function that returns a promise of nothing in particular.
			//
			// `reject` is deliberately not modelled. A rejected value arrives at a `catch`
			// handler or as a thrown exception, which is a control-flow edge the IR does
			// not carry, and pretending it arrives at the await's result would be wrong
			// about where the value goes rather than merely incomplete.
			{Symbol: "Promise", CallbackArg: 0, ResolverParam: argIndex(0), ResolverArg: 0,
				Note: "resolved out of the promise executor"},

			{Method: "then", CallbackArg: 0, CallbackParam: 0, Note: "promise continuation"},
			{Method: "forEach", CallbackArg: 0, CallbackParam: 0, Note: "element"},
			{Method: "map", CallbackArg: 0, CallbackParam: 0, Note: "element"},
			{Method: "filter", CallbackArg: 0, CallbackParam: 0, Note: "element"},
			{Method: "find", CallbackArg: 0, CallbackParam: 0, Note: "element"},
			{Method: "flatMap", CallbackArg: 0, CallbackParam: 0, Note: "element"},
			{Method: "some", CallbackArg: 0, CallbackParam: 0, Note: "element"},
			{Method: "every", CallbackArg: 0, CallbackParam: 0, Note: "element"},
			{Method: "reduce", CallbackArg: 0, CallbackParam: 1, Note: "element"},
		},

		Controls: []ControlRule{
			{Name: "requireAuth", Kind: "authentication"},
			{Name: "requireUser", Kind: "authentication"},
			{Name: "authenticate", Kind: "authentication"},
			{Name: "isAuthenticated", Kind: "authentication"},
			{Name: "ensureAuthenticated", Kind: "authentication"},
			{Name: "verifyToken", Kind: "authentication"},
			// The sibling of the two names above it, and the one linkwarden writes on
			// the first line of every API route it serves: `verifyUser({req, res})`
			// resolves the session and answers the request itself when there is none.
			{Name: "verifyUser", Kind: "authentication"},
			// Names real frameworks actually use, alongside the generic ones.
			{Name: "jwtAuth", Kind: "authentication"},
			{Name: "authGuard", Kind: "authentication"},
			{Name: "passport", Kind: "authentication"},
			{Name: "requireLogin", Kind: "authentication"},
			{Name: "loginRequired", Kind: "authentication"},
			{Name: "requireAdmin", Kind: "authorization"},
			{Name: "requireRole", Kind: "authorization"},
			{Name: "authorize", Kind: "authorization"},
			{Name: "checkPermission", Kind: "authorization"},
			{Name: "requireTenant", Kind: "authorization"},
			{Name: "adminGuard", Kind: "authorization"},
			{Name: "permissionGuard", Kind: "authorization"},
			{Name: "rolesGuard", Kind: "authorization"},
			{Name: "requirePermission", Kind: "authorization"},

			// Throttling. Usually applied everywhere by design, in which case the
			// population analysis correctly reports nothing: a control on every entry
			// point distinguishes none of them. What it catches is the endpoint that was
			// left out of a limiter its peers all carry, which is the shape of CWE-770.
			{Name: "rateLimit", Kind: "rate-limit"},
			{Name: "rateLimiter", Kind: "rate-limit"},
			{Name: "limiter", Kind: "rate-limit"},
			{Name: "throttle", Kind: "rate-limit"},
			{Name: "throttler", Kind: "rate-limit"},
			{Name: "ThrottlerGuard", Kind: "rate-limit"},
			{Name: "slowDown", Kind: "rate-limit"},

			// Anti-CSRF. Matched on the word alone, because every spelling a project uses
			// contains it: csurf, csrfProtection, doubleCsrfProtection, verifyCsrf.
			//
			// This is the control the population analysis is best suited to, and the
			// reason is that CSRF protection is not universally required. A token buys
			// nothing on an API authenticated by a bearer header, and half the programs
			// in the world are that. So "this route has no CSRF middleware" is not a
			// finding and never will be; "this route has no CSRF middleware and its peers
			// do" is one, because the program has already declared that its routes are
			// reached with a cookie.
			{Name: "csrf", Kind: "csrf"},
			{Name: "xsrf", Kind: "csrf"},
		},

		// Values whose own shape is the defect. Every one of these was run across twenty-eight
		// production repositories before it was written down, and the count that survived
		// outside test files is in the comment beside it. Nothing here scores entropy or
		// looks at the name of the variable holding the value: a shape a credential
		// either has or does not is the whole of the test, and it is the reason this kind
		// can be trusted without a second thought.
		Literals: []LiteralRule{
			{
				ID:                "regex-capture-arity-not-checked",
				RegexCaptureArity: true,
				CWE:               "CWE-129",
				Finding:           "Regular-expression capture read beyond the pattern's arity",
				Reason:            "this index names a capture group the pattern does not have, so the value is always undefined even when the expression matches",
				Rationale:         "the regex literal fixes the number of capture groups and the indexed read exceeds it",
			},
			{
				// `postgres://user:hunter2@db.internal/app`. Five on the clean corpus and
				// all five real: three vendor demo credentials in database engine
				// documentation, a Firebird default, and a developer script.
				//
				// The one thing that shares the shape and not the meaning is a format
				// example, and superset ships eighteen. Every one carries a bracket, a
				// parenthesis or a space, and a URL carries none of those.
				ID:          "credential-in-url",
				Pattern:     `^[a-z][a-z0-9+.\-]*://[^/:@\s]+:[^/@\s]+@[^/\s]`,
				ExceptChars: "[]()<>|$ {}%\t",
				// The one shape in this kind whose weight is genuinely not in the source.
				// `postgres://app:X@localhost/dev` is a developer's local password and
				// `postgres://app:X@db.internal/app` is production, and the string does
				// not say which -- the difference is entirely about where it points. A
				// private key is a private key wherever it points, which is why the rest
				// of these gate and this one does not.
				DependsOnUse: "whether the host it names is reachable and the credential still live is not in the source: the same string is a developer's local password and a production one",
				CWE:          "CWE-798",
				Finding:      "Credential written into a connection string",
				Reason:       "the password is in every clone of the repository, and a connection string is copied between environments far more often than it is rewritten",
				Rationale:    "a URL in the source carries a username and a password in its authority",
			},
			{
				// One on the clean corpus, and it is a real EC private key written into
				// an Apple Sign-In example.
				ID:        "private-key-block",
				Pattern:   `-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`,
				CWE:       "CWE-321",
				Finding:   "Private key written into the source",
				Reason:    "everyone who can read the repository can act as whatever this key identifies, and revoking it means reissuing every certificate or token it signed",
				Rationale: "the value is a PEM private key block",
			},
			{
				// One on the clean corpus: a signed token granting a valid enterprise
				// subscription until 2125, in a constant named for development. A token
				// is not a key, but anybody holding the repository can present it.
				ID:        "signed-token",
				Pattern:   `^eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}$`,
				CWE:       "CWE-798",
				Finding:   "Signed token written into the source",
				Reason:    "anybody holding the repository can present it, and it stays valid until it expires or the key that signed it is retired",
				Rationale: "the value is a signed JSON Web Token",
			},
			// The provider-issued identifiers. Each is a shape its issuer defined and
			// nothing else has, and each measured ZERO outside test files across the
			// whole clean corpus -- which is what a rule with no room to guess looks like.
			{
				ID: "aws-key-id", Pattern: `^(?:AKIA|ASIA)[0-9A-Z]{16}$`,
				CWE: "CWE-798", Finding: "AWS key identifier written into the source",
				Reason:    "the identifier names a key that can be tried against every AWS account endpoint until it is deactivated",
				Rationale: "the value has the shape AWS issues access key identifiers in",
			},
			{
				ID: "github-token", Pattern: `^gh[pousr]_[A-Za-z0-9]{36,255}$`,
				CWE: "CWE-798", Finding: "GitHub token written into the source",
				Reason:    "the token carries whatever the account it belongs to can do, and a repository is the one place it is certain to be read",
				Rationale: "the value has the shape GitHub issues tokens in",
			},
			{
				// Digit groups are required. Without them `xoxb-oauth-bot-token` matches,
				// and seventy-three test fixtures across the clean corpus are spelled
				// exactly that way.
				ID: "slack-token", Pattern: `^xox[baprse]-\d{9,}-\d{9,}-[A-Za-z0-9]{16,}$`,
				CWE: "CWE-798", Finding: "Slack token written into the source",
				Reason:    "the token can read and post as whatever installed it, in every channel that installation can reach",
				Rationale: "the value has the shape Slack issues tokens in",
			},
			{
				ID: "stripe-key", Pattern: `^(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}$`,
				CWE: "CWE-798", Finding: "Stripe secret key written into the source",
				Reason:    "a live secret key moves money, and a test key reveals the account it belongs to",
				Rationale: "the value has the shape Stripe issues secret keys in",
			},
			{
				ID: "google-api-key", Pattern: `^AIza[0-9A-Za-z_\-]{35}$`,
				CWE: "CWE-798", Finding: "Google API key written into the source",
				Reason:    "the key is billed to the project that issued it and is usable by anybody who reads the repository",
				Rationale: "the value has the shape Google issues API keys in",
			},
			{
				ID: "npm-token", Pattern: `^npm_[A-Za-z0-9]{36}$`,
				CWE: "CWE-798", Finding: "npm token written into the source",
				Reason:    "the token can publish under whatever the account owns, which is how a package gets replaced rather than merely read",
				Rationale: "the value has the shape npm issues tokens in",
			},
		},
	}
}

// LiteralRule is a weakness visible in a written-down value and nothing else.
//
// The narrowest rule kind in the model, and the only one whose subject has no context at
// all: not an argument, not a destination, not a flow. `AKIA` followed by sixteen
// upper-case characters is an AWS key identifier wherever it appears, and a program that
// contains one contains a credential.
//
// Every rule here is a shape a value either HAS or does not. There is deliberately no
// entropy score and no proximity to a variable named `secret`: both are ways of guessing,
// and every one of the eight shapes shipped here was measured across twenty-eight production
// repositories before it was written, with the ones that fired on anything other than a
// real key left out.
type LiteralRule struct {
	ID string
	// RegexCaptureArity reports an indexed capture that the literal cannot contain. It
	// shares this rule kind because the complete evidence starts in the regex literal;
	// the index is retained only to identify which part of that literal was read.
	RegexCaptureArity bool
	// Pattern is a regular expression the value must match. Compiled once at model
	// construction, because this runs against every literal in the program.
	Pattern string
	// ExceptChars disqualifies a value containing any of these characters.
	//
	// DependsOnUse names what the source does not say, for a shape whose weight turns on
	// something outside it. Reported, never gating, and the report prints the reason.
	DependsOnUse string
	// The one thing that looks like a credential in a URL and is not is a DOCUMENTATION
	// TEMPLATE: `engine+driver://user:password@host[:port]/dbname[?key=value]`. Superset
	// ships eighteen of them and every single one carries a bracket, a parenthesis, an
	// angle bracket or a space. A URL carries none of those.
	ExceptChars string

	CWE       string
	Finding   string
	Reason    string
	Rationale string

	re *regexp.Regexp
}

// Matches reports whether a value has this rule's shape.
func (r LiteralRule) Matches(text string) bool {
	if r.re == nil || text == "" {
		return false
	}
	if r.ExceptChars != "" && strings.ContainsAny(text, r.ExceptChars) {
		return false
	}
	return r.re.MatchString(text)
}

// ClientRoleRule is the vocabulary for one question about a written-down value: does THIS
// program rely on it being secret?
//
// It is the same question the weak-digest rule asks, one level down. A digest matters
// when the program TRUSTS it; a credential matters when the program's own security rests
// on nobody else having it. Neither question is answered by what the value says.
//
// The measurement that forced it: 27 of the 56 false positives left across ten production
// repositories were public client identifiers, all 27 in yt-dlp -- Firebase web API keys,
// a Google Drive playback key, Adobe Primetime `software_statement` attestations. Every
// one is a value the third-party site publishes in its own web client, and yt-dlp is a
// CLIENT of every site it has an extractor for: there is no server in that program whose
// door any of those keys opens.
//
// The fix is deliberately NOT a list of vendor prefixes. `AIzaSy` happens to be
// recognisable and the next provider's will not be, and an unrestricted Google key can
// genuinely be abused for billing -- the shape is not what makes a value public, the USE
// is. So what is written down here is the shape of a USE:
//
//   - RequestParts name the places an outbound request keeps its parameters. A value the
//     program files under one of them is being handed to somebody else's service.
//   - Schemes recognise the moment the service is NAMED in the same breath: a call that
//     carries an absolute URL written in the source is a call to that address.
//   - SecretParts name the request parts whose own name says the value is the program
//     proving who it is rather than saying which client it is. A `client_secret` posted
//     to a token endpoint and a `client_id` posted to the same endpoint travel
//     identically and are not the same thing, and the key they are filed under is the
//     only place the program says which is which.
//   - Carriers are calls that hand their argument onward unchanged. Without them the
//     value stops at `json.dumps(...)` and the request two lines later is invisible.
//
// Everything here is matched on the option KEY the frontends already read, never on the
// value. Nothing scores entropy and nothing looks at what a variable is called.
type ClientRoleRule struct {
	// RequestParts are the leading segments of an option path that make the option part
	// of an outbound request: `query.key`, `headers.Referer`, `data.client_id`.
	RequestParts []string
	// SecretParts are the option names under which a value is the program's own
	// credential rather than its name. Matched on the option's LEAF segment as a word,
	// because `data.client_secret` and `headers.Authorization` are compound.
	//
	// `token` is in this list and is deliberately absent from the configuration-key list
	// that the store rule uses, and the two are not in conflict: a configuration key
	// holding the word token held a URL or a header name in every one of twenty-eight
	// repositories, while a request PART named token holds the token.
	SecretParts []string
	// Schemes are the prefixes that make a literal an absolute URL, which is how the
	// engine recognises that a call names the service it is talking to.
	Schemes []string
	// Carriers are calls that pass their argument along unchanged -- a serializer, an
	// encoder, a string join. A value reaching one of these is still the same value.
	Carriers []string
	// Budget bounds the walk. A role is decided from a bounded neighbourhood of the
	// literal or it is not decided at all: an unbounded search over a program with eight
	// thousand functions would answer a different question on every repository.
	Budget int
}

// IsRequestPart reports whether an option path's first segment is part of an outbound
// request.
func (r ClientRoleRule) IsRequestPart(path string) bool {
	head, _, _ := strings.Cut(strings.ToLower(path), ".")
	for _, p := range r.RequestParts {
		if head == p {
			return true
		}
	}
	return false
}

// NamesASecret reports whether an option path's leaf says the value is the program's own
// credential. Matched as a word inside the leaf, so `client_secret`, `X-Api-Signature`
// and `apiSecret` all hold and `secretariat` does not.
func (r ClientRoleRule) NamesASecret(path string) bool {
	leaf := strings.ToLower(path)
	if i := strings.LastIndex(leaf, "."); i >= 0 {
		leaf = leaf[i+1:]
	}
	for _, w := range r.SecretParts {
		if containsWord(leaf, w) {
			return true
		}
	}
	return false
}

// IsURL reports whether a literal names a service by address.
func (r ClientRoleRule) IsURL(text string) bool {
	low := strings.ToLower(strings.TrimSpace(text))
	for _, s := range r.Schemes {
		if strings.HasPrefix(low, s) {
			return true
		}
	}
	return false
}

// IsCarrier reports whether a call hands its argument onward unchanged.
func (r ClientRoleRule) IsCarrier(symbol, method string) bool {
	sym := strings.ToLower(symbol)
	meth := strings.ToLower(method)
	for _, c := range r.Carriers {
		if meth == c {
			return true
		}
		if sym == c || strings.HasSuffix(sym, "."+c) {
			return true
		}
	}
	return false
}

// containsWord reports whether want appears in s as a whole word, where a word is
// bounded by anything that is not a letter or a digit.
//
// This is the test that separates `client_secret` from `secretariat` and, in the
// configuration keys the store rule reads, `email_password_status` from `password`. A
// substring match on a compound identifier is how a glyph table came to be reported as a
// credential.
func containsWord(s, want string) bool {
	if want == "" {
		return false
	}
	for i := 0; i+len(want) <= len(s); i++ {
		if s[i:i+len(want)] != want {
			continue
		}
		if i > 0 && isWordByte(s[i-1]) {
			continue
		}
		if j := i + len(want); j < len(s) && isWordByte(s[j]) {
			continue
		}
		return true
	}
	return false
}

func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// builtinClientRole is the vocabulary the role judgement is made in. Every name here was
// taken from a call the corpus actually writes, not from a library's documentation.
func builtinClientRole() ClientRoleRule {
	return ClientRoleRule{
		// The option names the two frontends flatten for a request: `query=`, `params=`,
		// `headers=`, `data=`, `json=`, `body=`, `form=`. A value filed under one of
		// these is in the request, whoever the request is to.
		RequestParts: []string{
			"query", "params", "qs", "searchparams", "search_params",
			"data", "json", "body", "form", "formdata", "form_data",
			"headers", "header", "payload", "cookies", "fields",
		},
		// The request parts whose name says the value is this program's own credential.
		// A Stripe secret key travels to Stripe exactly as a Firebase web key travels to
		// Google; what separates them is that one goes in the Authorization and the
		// other goes in the query, and the program says which.
		SecretParts: []string{
			"secret", "password", "passwd", "pwd", "signature", "sig", "private",
			"privatekey", "auth", "authorization", "token", "credential", "credentials",
			"apikey", "api_key", "accesskey", "access_key", "secretkey", "secret_key",
		},
		Schemes: []string{"http://", "https://", "ws://", "wss://"},
		// A serializer, an encoder and the two spellings of a form body. Each of these
		// returns its argument in a different container and nothing else.
		Carriers: []string{
			"json.dumps", "json.stringify", "encode", "decode", "str", "string",
			"urlencode", "urlencode_postdata", "urlencode_plus", "quote", "quote_plus",
			"b64encode", "b64decode", "join", "format", "strip", "lower", "upper",
			"tostring", "buffer.from", "new urlsearchparams", "urlsearchparams",
		},
		// Four steps out from the literal. Measured: the deepest real chain in the
		// corpus is a class constant, read in a method, handed to a helper, serialised,
		// and posted -- and a fifth step buys nothing but reach into unrelated code.
		Budget: 4,
	}
}

// CallShape is a weakness visible in a call's own arguments, with no dataflow involved.
//
// A third analysis kind, and the one a large part of the CWE catalog actually needs.
// `createHash("md5")` is weak wherever it is written; nothing has to reach it and no
// caller has to control anything. Bending taint into that shape would mean inventing a
// source for a defect that has none.
//
// Because these are not flows, ADR-009 does not govern them: a weak hash in a utility file
// nothing routes to is still a weak hash. Anchoring to the enumerated surface is a rule
// about ASSERTIONS OVER A SURFACE, and this is an assertion about a line of code.
// ArgCondition is a test against one argument's literal value.
type ArgCondition struct {
	// Keyword names an option to test instead of a position. Conjunctions are how
	// misconfiguration usually reads: one option is dangerous only because another is
	// set, and `credentials: true` is fine until the origin is reflected back.
	Keyword  string
	ArgIndex int
	// AnyOf are the values that satisfy it, compared without regard to case.
	AnyOf []string
	// Substring matches when the literal CONTAINS one of AnyOf rather than equalling
	// it, which is what makes `connect.sid` and `refresh_token` both read as credentials.
	Substring bool
	// Absent holds when the named option is NOT set at all, which is how two channels
	// can describe the same call and exactly one of them match. A session cookie and a
	// persistent one are the same call with and without an expiry, and reporting both
	// would double every cookie finding.
	Absent bool

	// NotLiteral holds when the argument was NOT written as a literal, which is how a
	// call can prove a value is not a secret.
	//
	// lnbits sets `is_lnbits_user_authorized` to the string "true" beside a real session
	// cookie that is correctly HttpOnly. The name reads as a credential and the value
	// proves it is not one: a secret cannot be a constant in the source, because
	// everybody who can read the repository would have it. Without this the rule reported
	// three flag cookies in one application and stayed correctly silent on the actual
	// token two lines above.
	NotLiteral bool

	// HoldsWhenUnread keeps a veto from going silent on an argument nobody wrote down.
	//
	// A condition normally fails when the argument it names is not a literal, because
	// nothing is assumed about a value decided at runtime. That is the right default for
	// a condition that must ESTABLISH something. It is the wrong one for a condition that
	// only DISQUALIFIES: `createCipheriv(alg, key, iv)` puts an initialisation vector in
	// the third slot in every mode that has one and requires the slot to be empty in ECB,
	// which has none -- so reading the third argument without the first judges an
	// argument whose meaning has not been established. Written as a veto on ECB rather
	// than as a list of the modes that do take an IV, because an algorithm named by a
	// variable is where the engine knows least, and trading four false findings for an
	// unknown number of silences is not a precision fix.
	HoldsWhenUnread bool

	// NoneOf disqualifies, and is checked first.
	//
	// A double-submit CSRF token is the case that requires it. `csrf_token` contains
	// "token" and is a credential by any reasonable reading, and it is deliberately
	// readable by script -- that is the entire mechanism, since the page has to echo it
	// back in a header. Reporting it as needing HttpOnly would be advising a change that
	// breaks the protection it is part of.
	NoneOf []string
}

// Holds reports whether a call satisfies this condition. An argument that was not
// written as a literal does not satisfy it: nothing is assumed about a value decided
// at runtime.
func (a ArgCondition) Holds(literals map[int]string) bool {
	var lit string
	var ok bool
	if a.Absent {
		want := strings.ToLower(a.Keyword)
		for i, l := range literals {
			if i >= 0 {
				continue
			}
			if key, _, cut := strings.Cut(l, "="); cut && lastKeySegment(key) == want {
				return false
			}
		}
		return true
	}
	if a.NotLiteral {
		lit, written := literals[a.ArgIndex]
		// A value the frontend could not read is not a value that was written down.
		return !written || lit == "?"
	}
	if a.Keyword != "" {
		want := strings.ToLower(a.Keyword)
		for i, l := range literals {
			if i >= 0 {
				continue
			}
			key, value, cut := strings.Cut(l, "=")
			if cut && lastKeySegment(key) == want {
				lit, ok = value, true
				break
			}
		}
	} else {
		lit, ok = literals[a.ArgIndex]
	}
	if !ok {
		return a.HoldsWhenUnread
	}
	lit = strings.ToLower(lit)
	for _, veto := range a.NoneOf {
		if strings.Contains(lit, strings.ToLower(veto)) {
			return false
		}
	}
	// No AnyOf means "any literal that survived the vetoes". A condition can then say
	// what a value must NOT be without having to enumerate what it may be.
	if len(a.AnyOf) == 0 {
		return true
	}
	for _, want := range a.AnyOf {
		want = strings.ToLower(want)
		if lit == want || (a.Substring && strings.Contains(lit, want)) {
			return true
		}
	}
	return false
}

type CallShape struct {
	ID string

	// Matching, by imported symbol or by method name.
	Symbol string
	Method string
	// AnyCall matches regardless of what is being called, for an option whose NAME is
	// the evidence.
	//
	// `rejectUnauthorized: false` means exactly one thing in Node and means it wherever
	// it appears -- on an https.Agent, on tls.connect, on an axios instance, inside a
	// library's own config. Enumerating the callees would be a list that is wrong the
	// moment somebody uses a client nobody thought of, and would be less precise than
	// the option name already is.
	AnyCall bool

	// ArgIndex is the argument that decides it. A negative index addresses a keyword
	// argument, which the frontends record as "name=value" because `verify=False` means
	// the same thing wherever it is written.
	ArgIndex int
	// Disallowed values, compared without regard to case. A literal is required: this
	// says nothing about a value computed at runtime, and says nothing loudly rather
	// than guessing.
	Disallowed []string
	// Keyword reads a NAMED option's value instead of a position.
	//
	// `createConnection({host, user, password: "hunter2"})` puts the secret where the
	// library asks for it, which is a name rather than an index -- and the same name in
	// every library that asks for one.
	Keyword string

	// ReceiverFromCall narrows a method-name shape by WHAT MADE THE RECEIVER, following
	// plain assignments back to the call that produced it.
	//
	// `extractall` is a method on two different classes. A tar member can be a symbolic
	// link and a zip member cannot, and only tarfile has the parameter that decides what
	// a member may be -- so a rule about the missing parameter must know which archive it
	// is looking at, and the name of the variable will not say.
	ReceiverFromCall []string

	// Always matches on the SYMBOL alone, for a call that is a defect by existing.
	//
	// `tempfile.mktemp()` returns a name and does not create the file, so anything can
	// win the race to create it first; there are no arguments to inspect and no way to
	// call it safely. A shape that must look at an argument cannot express that at all.
	Always bool

	// MaskedBits matches when the argument is a number with these bits set.
	//
	// A file mode is the case: what makes 0o777 wrong is not the number but the
	// world-writable bit inside it, and 0o666, 0o707 and 0o1777 are wrong for exactly the
	// same reason. Enumerating them would be a list that is wrong the moment somebody
	// picks a mode nobody thought of; testing the bit is the actual rule.
	//
	// Parsed base-aware, because the frontends hand this over differently: TypeScript
	// records the numeric literal as written (`0o777`) and Python records what it
	// evaluated to (`511`), and both are the same mode.
	MaskedBits *int

	// BelowValue matches when the argument is a NUMBER written in the call and smaller
	// than this. A work factor is the case that needs it: `bcrypt.hash(pw, 4)` is wrong
	// for a reason no list of forbidden strings can express, and the answer is a
	// threshold rather than an enumeration.
	//
	// A value computed at runtime is not a number written in the call and is not
	// matched, which keeps this at the precision that makes the kind worth having.
	BelowValue *int

	// AboveValue is the mirror, for a number that is wrong by being too LARGE. A session
	// lifetime is the case: nothing about a cookie says what a reasonable one is, but a
	// credential cookie good for a year is a stolen credential good for a year.
	//
	// Units are not guessable from a keyword, so the threshold lives on a rule that
	// already knows which call it is reading: express counts milliseconds and Flask
	// counts seconds, and the same name means different things in each.
	AboveValue *int

	// AnyLiteral matches when the argument was written as a literal at all, whatever it
	// says. For an argument that is supposed to hold a secret, being written down IS the
	// defect and its contents are beside the point -- and the same test is what makes it
	// precise, because a secret read from the environment or a vault is not a literal
	// and never matches.
	AnyLiteral bool

	// ArgFromModuleScope names an argument that must resolve to a value bound at MODULE
	// scope -- computed once when the file was loaded, and the same on every call after.
	//
	// An initialisation vector is the case. It must be different for every message, and
	// `const IV = randomBytes(16)` at the top of a file is different for every PROCESS,
	// which is not the same thing and looks correct at a glance because a random number
	// is involved. A literal IV is already caught by reading the literal; this catches the
	// version that has no literal to read.
	ArgFromModuleScope *int

	// MissingArg names a positional argument whose ABSENCE, at a call that otherwise
	// matches, is the defect.
	//
	// `window.open(url, "_blank")` hands the opened page a live reference back to this
	// one through window.opener, and the third argument is where `noopener` would have
	// gone. Nothing wrong was written down; the right thing was left out, and the count
	// of arguments is the whole evidence.
	MissingArg *int

	// ExternalDestinationArg names the argument whose destination must be capable of
	// leaving the page's origin for this shape to be a defect.
	//
	// `window.open("/Resource/123", "_blank")` does leave an opener reference behind,
	// but it hands that reference to another page in the same application -- not to the
	// untrusted origin the opener rule is about. A network-path reference is deliberately
	// not local: `//host` replaces the authority, and browsers normalize `/\host` to the
	// same shape. The distinction belongs to the destination rather than to medplum's
	// resource-route spelling, so the analysis reads the value and any local helper that
	// returned it.
	ExternalDestinationArg *int

	// InputClass requires the receiver or one argument to carry a classification the
	// dataflow analysis already established. This is still a judgement about the call:
	// `upload.read()` and `local_file.read()` have the same written shape, and what the
	// call was handed is the fact that separates remote input from an ordinary file.
	// InputReceiver and InputArg say which operand the API consumes.
	InputClass    string
	InputReceiver bool
	InputArg      *int
	// RemoteInput refuses operator and internal sources. A management command may read
	// its whole input safely because the person choosing it already controls the host;
	// the same allocation on an HTTP path is available to anyone who can reach it.
	RemoteInput bool

	// RequiredKeyword names an option whose ABSENCE is the defect, which is the shape
	// most misconfiguration takes: nothing wrong was written down, the right thing was
	// left out.
	//
	// Absence is only claimable where the option keys are knowable, and OptionsArg says
	// where to look -- a positional index for a language that passes an options object,
	// -1 for one that uses keyword arguments. Where the options were built elsewhere the
	// answer is silence, not a finding (ADR-003).
	RequiredKeyword string
	OptionsArg      int

	// RequiredAnyOf widens an absence rule: the absence is claimed only when NONE of
	// these keys appears anywhere in the call.
	//
	// A token's expiry can be written two ways -- `expiresIn` in the signing options, or
	// an `exp` claim in the payload -- and a rule that looked for only the first reported
	// eighteen calls across the clean corpus, the two examined both false.
	RequiredAnyOf []string

	// AlsoEnumerated names further argument positions whose KEY SET must also have been
	// read before an absence is claimed. A payload built by another function says nothing
	// about whether it contains an expiry.
	AlsoEnumerated []int

	// OptionsMustBeWritten requires the options argument to actually be there before an
	// absence is claimed.
	//
	// A missing options argument usually IS the absence -- `res.cookie(name, value)`
	// genuinely has no httpOnly. It is not always: `jwt.sign(payload, key)` can carry its
	// expiry as an `exp` claim inside the payload, so a call with no options argument
	// says nothing about whether the token expires. The difference is per-rule, so the
	// rule states it.
	OptionsMustBeWritten bool

	// Qualifiers are further conditions on the SAME call, all of which must hold.
	//
	// Cookie attributes are the case that needed it. Whether a cookie ought to be
	// HttpOnly is a question about what the cookie CARRIES: a session token must never
	// be readable by script, and a theme preference is written to be read by script.
	// The call carries the answer, because argument zero is the cookie's name and real
	// code writes it as a literal -- `jwt`, `access_token`, `refresh_token`,
	// `csrf_token` all appear in the corpus exactly that way.
	//
	// A name list is the weakest kind of rule in this project, and it is used here in
	// the safe direction: to NARROW an existing match, never to make one. The worst it
	// can do is stay quiet about a session cookie somebody named `q7`, which is a
	// stated false negative rather than a false alarm.
	Qualifiers []ArgCondition

	// PatternArg names an argument that holds a regular expression, written as a literal
	// or bound to one by name. The shape matches only when that pattern is one that can be
	// made to backtrack exponentially (see CatastrophicPattern).
	//
	// The channel of the same name asks this at a call that is HANDED the caller's string.
	// A validation schema never is: `z.string().regex(DOMAIN)` describes a check, and the
	// string it will run on arrives later, inside whatever the framework calls to parse the
	// request. The pattern and the reachability are both plainly written and they are
	// written in different places, which is exactly what this kind is for.
	PatternArg *int

	// EntryReachable requires the call to sit in a function an enumerated entry point
	// reaches. A shape that says "a caller's input meets this" has claimed something about
	// the attack surface and must be held to it (ADR-009): a schema in a script, in a test,
	// or in a module nothing routes to has no caller and is not a finding.
	EntryReachable bool

	// SymbolContains narrows a method-name shape by the CHAIN it was called on, which the
	// TypeScript frontend records in the callee symbol: `z.string().trim().regex` names
	// every step that built the receiver. `regex` alone is a common enough method name;
	// `regex` on something a validation library made is not.
	SymbolContains []string

	// DependsOnUse marks a shape whose judgement turns on what the result is USED for,
	// which the call does not carry.
	//
	// A broken hash is the clearest case. `createHash("md5")` is the same call whether it
	// digests a password or builds a cache key, and the Gravatar protocol REQUIRES the MD5
	// of an email address. Measured across sixteen production repositories the rule
	// produced 26 findings, every one a filename, an ETag, a content key or Gravatar, and
	// every one gating.
	//
	// So it is reported and never gates, and says why. Deciding it properly means asking
	// where the digest goes -- whether it reaches somewhere collision resistance is what
	// makes the thing work -- and that is a flow question this kind cannot answer alone.
	//
	// Confidence is NOT used to express this. Confidence means how well the call graph
	// resolved (ADR-005) and it resolved perfectly: the algorithm is a literal. Lowering
	// it would be lying about a different thing to get the gating behaviour wanted here.
	//
	// The value is the reason, printed as written, so each rule says its own truth rather
	// than sharing one vague sentence.
	DependsOnUse string

	// ConfigurationEnabled marks a behavior whose reachability may be controlled by
	// an enclosing deployment condition. The call remains a finding: environment flags
	// are frequently unset or wrong. The condition changes gating through DependsOnUse,
	// not the confidence of a call the frontend resolved correctly.
	ConfigurationEnabled bool

	// ExcludeTestModule keeps an absence in test-only setup from being treated as a
	// deployment default. Tests routinely issue deliberately short-lived-in-practice
	// tokens without an expiry; no application caller can ever receive them.
	ExcludeTestModule bool

	CWE       string
	Finding   string
	Reason    string
	Rationale string
}

// Matches reports whether a literal argument value is one this shape forbids.
func (c CallShape) Matches(literal string) bool {
	if c.Always {
		return true
	}
	if c.MaskedBits != nil {
		n, err := strconv.ParseInt(strings.TrimSpace(literal), 0, 64)
		return err == nil && n&int64(*c.MaskedBits) != 0
	}
	if c.BelowValue != nil {
		n, err := strconv.Atoi(strings.TrimSpace(literal))
		return err == nil && n < *c.BelowValue
	}
	if c.AboveValue != nil {
		n, err := strconv.Atoi(strings.TrimSpace(literal))
		return err == nil && n > *c.AboveValue
	}
	if c.AnyLiteral {
		return true
	}
	for _, bad := range c.Disallowed {
		if strings.EqualFold(literal, bad) {
			return true
		}
	}
	return false
}

// at is a pointer to an int, for the optional index fields.
func at(i int) *int { return &i }

func builtinCallShapes() []CallShape {
	// What a cookie CARRIES decides whether its attributes matter. A session token must
	// never be readable by script; a theme preference is written to be read by script,
	// and there is nothing to fix about it. The name in argument zero is the only
	// evidence of that available at the call, and real code supplies it: `jwt`,
	// `access_token`, `refresh_token`, `connect.sid` all appear in the corpus written as
	// literals.
	//
	// `login` is deliberately absent. It matched `loginRedirect`, which holds a path.
	credentialCookie := []ArgCondition{
		{
			ArgIndex:  0,
			Substring: true,
			AnyOf:     []string{"session", "sess", "sid", "jwt", "token", "auth", "remember"},
			NoneOf:    []string{"csrf", "xsrf"},
		},
		// And the value must not be written in the source. A cookie set to a constant
		// carries a flag, not a credential.
		{ArgIndex: 1, NotLiteral: true},
	}

	return []CallShape{
		{
			// Measured before it was written (ADR-015). The raw shape -- `read()` on a
			// receiver carrying untrusted-input -- occurred twice across the ten production
			// repositories: linkding's HTTP bookmark import and its management-command
			// importer. Requiring REMOTE trust removed the command and left one finding.
			// After the independently missing DRF action surface was lowered, the raw count
			// became three and the remote count became two; both remote sites are the two
			// independently confirmed uploads this rule was meant to state.
			// A read with any positional size is silent, because the call then materialises
			// an amount the program chose rather than the whole object the caller supplied.
			ID: "remote-input-read-without-size", Method: "read", MissingArg: at(0),
			InputClass: "untrusted-input", InputReceiver: true, RemoteInput: true,
			EntryReachable: true,
			CWE:            "CWE-770",
			Finding:        "Remote input materialized without a size bound",
			Reason:         "the call reads the whole object a remote caller supplied into memory, and no size argument limits how much that operation accepts",
			Rationale:      "read() is called on request-derived input without the positional size argument",
		},
		{
			// A protocol version nobody should still be negotiating. Naming one in the
			// call is asking for it specifically, which is different from accepting
			// whatever a peer offers.
			ID: "obsolete-tls", AnyCall: true, Keyword: "secureProtocol",
			Disallowed: []string{"SSLv2_method", "SSLv3_method", "TLSv1_method", "TLSv1_1_method"},
			CWE:        "CWE-757",
			Finding:    "Obsolete TLS version requested",
			Reason:     "these versions have known breaks and are refused by everything current, so naming one is asking for the weaker of what is on offer",
			Rationale:  "the connection names an obsolete protocol version",
		},
		{
			ID: "obsolete-tls", AnyCall: true, Keyword: "minVersion",
			Disallowed: []string{"SSLv3", "TLSv1", "TLSv1.1"},
			CWE:        "CWE-757",
			Finding:    "Obsolete TLS version accepted",
			Reason:     "these versions have known breaks and are refused by everything current, so accepting one is accepting the weaker of what is on offer",
			Rationale:  "the connection accepts an obsolete protocol version",
		},

		// --- randomness, signatures and written-down secrets ------------------------
		{
			// A generator seeded with a constant produces the SAME sequence on every run
			// and on every machine. Whatever it is used for, it is not a surprise to
			// anyone who can read this line.
			ID: "fixed-seed", Symbol: "random.seed", ArgIndex: 0, AnyLiteral: true,
			CWE:       "CWE-336",
			Finding:   "Random generator seeded with a constant",
			Reason:    "seeding with a constant makes every run produce the same sequence, so the numbers are the same for everybody who reads this line",
			Rationale: "seed() is given a value written in the call",
		},
		{
			ID: "fixed-seed", Symbol: "numpy.random.seed", ArgIndex: 0, AnyLiteral: true,
			CWE:       "CWE-336",
			Finding:   "Random generator seeded with a constant",
			Reason:    "seeding with a constant makes every run produce the same sequence, so the numbers are the same for everybody who reads this line",
			Rationale: "seed() is given a value written in the call",
		},
		{
			// Signature verification switched OFF by name. Decoding a token to LOOK at it
			// is ordinary -- reading the issuer to pick a key, reading the expiry -- and
			// 58 sites across the clean corpus say so. What is not ordinary is telling
			// the verifier not to verify.
			ID: "unverified-signature", AnyCall: true, Keyword: "verify_signature",
			Disallowed:   []string{"false"},
			DependsOnUse: "reading a token to LOOK at it is ordinary -- capping an expiry, routing on an issuer, logging a subject -- and verifying it first would be pointless for those. What makes an unverified decode a defect is whether the claims are then believed, and the call does not say. Measured across the clean corpus the rule found seven, four of them reads of an expiry the code had just been handed over TLS",
			CWE:          "CWE-347",
			Finding:      "Token accepted without checking its signature",
			Reason:       "a token whose signature is not checked is a token anyone can write, so everything it claims is the sender's to choose",
			Rationale:    "signature verification is switched off in the call",
		},
		{
			// PyJWT's older spelling, `jwt.decode(token, verify=False)`. Narrowed by the
			// METHOD rather than by a companion keyword: the qualifier here used to be
			// "the call also names algorithms", which is what a JWT decode usually
			// carries and not what it must -- and the one in the vulnerable corpus
			// carries no algorithms at all, so the rule said nothing about the plainest
			// possible way to write this weakness.
			//
			// `decode` is the discriminator that matters. `requests.get(url,
			// verify=False)` turns off TLS verification and is a different weakness with
			// a rule of its own; nothing else in either corpus decodes with a verify flag.
			ID: "unverified-signature", Method: "decode", Keyword: "verify",
			Disallowed:   []string{"false"},
			DependsOnUse: "reading a token to LOOK at it is ordinary -- capping an expiry, routing on an issuer, logging a subject -- and verifying it first would be pointless for those. What makes an unverified decode a defect is whether the claims are then believed, and the call does not say. Measured across the clean corpus the rule found seven, four of them reads of an expiry the code had just been handed over TLS",
			CWE:          "CWE-347",
			Finding:      "Token accepted without checking its signature",
			Reason:       "a token whose signature is not checked is a token anyone can write, so everything it claims is the sender's to choose",
			Rationale:    "signature verification is switched off in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "mysql.createConnection", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "mysql.createConnection", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "mysql2.createConnection", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "mysql2.createConnection", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "mysql.createPool", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "mysql.createPool", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "mysql2.createPool", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "mysql2.createPool", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "pg.Client", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "pg.Client", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "pg.Pool", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "pg.Pool", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "mongoose.connect", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "mongoose.connect", Keyword: "pass", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "pass", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "mongoose takes its credential as pass rather than password",
		},
		{
			ID: "hardcoded-password", Symbol: "mongoose.createConnection", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "mongoose.createConnection", Keyword: "pass", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "pass", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "mongoose takes its credential as pass rather than password",
		},
		{
			ID: "hardcoded-password", Symbol: "redis.createClient", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "redis.createClient", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "nodemailer.createTransport", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "nodemailer.createTransport", Keyword: "pass", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "pass", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "nodemailer takes its credential as auth.pass, which is read now that options one level down are",
		},
		{
			// ldapjs does not take a credential when the client is made: authentication
			// is a separate `bind(dn, password)` call, so the second ARGUMENT is where
			// the password is, not an option.
			ID: "hardcoded-password", Method: "bind", ArgIndex: 1, AnyLiteral: true,
			Qualifiers: []ArgCondition{{ArgIndex: 0, Substring: true, AnyOf: []string{"cn=", "uid=", "dn=", "ou="}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the second argument to bind() is the password, and the first is a distinguished name",
		},
		{
			ID: "hardcoded-password", Symbol: "psycopg2.connect", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "psycopg2.connect", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "pymysql.connect", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "pymysql.connect", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "MySQLdb.connect", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "MySQLdb.connect", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "pymongo.MongoClient", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "pymongo.MongoClient", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "sqlalchemy.create_engine", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "sqlalchemy.create_engine", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "redis.Redis", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "redis.Redis", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
		},
		{
			// smtplib's constructor takes no credential at all: `login(user, password)`
			// is where it goes, so the second argument is the one to read.
			ID: "hardcoded-password", Method: "login", ArgIndex: 1, AnyLiteral: true,
			Qualifiers: []ArgCondition{{ArgIndex: 0, NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the second argument to login() is the password, and the first is the account it belongs to",
		},
		{
			// TLS without a hostname check authenticates SOME valid certificate, not the
			// one belonging to the host being talked to. Any certificate any CA ever
			// issued will do.
			ID: "no-hostname-check", AnyCall: true, Keyword: "check_hostname",
			Disallowed: []string{"false"},
			CWE:        "CWE-297",
			Finding:    "Certificate hostname not checked",
			Reason:     "without a hostname check the connection accepts any valid certificate, not the one belonging to the host it is talking to",
			Rationale:  "check_hostname is set to False",
		},

		{
			// The `errorhandler` middleware exists to print a stack trace to the browser,
			// and its own documentation says to use it in development only. Whether the
			// program guards it with a NODE_ENV test is not the question: the guard is a
			// deployment fact and the middleware is in the bundle either way, so what a
			// scanner can say is that the application is one environment variable away
			// from serving its internals.
			//
			// Measured: two calls across the vulnerable corpus, both of them findings a
			// recall audit named, and none at all across twenty-eight production
			// repositories.
			ID: "development-error-handler", Symbol: "errorhandler.default", Always: true,
			CWE:                  "CWE-209",
			Finding:              "Development error handler installed",
			Reason:               "this middleware answers a failed request with the stack trace, the source line and the local variables, which describes the system to whoever provoked the failure",
			Rationale:            "errorhandler renders internal failure detail into the response",
			ConfigurationEnabled: true,
		},
		{
			ID: "development-error-handler", Symbol: "errorhandler", Always: true,
			CWE:                  "CWE-209",
			Finding:              "Development error handler installed",
			Reason:               "this middleware answers a failed request with the stack trace, the source line and the local variables, which describes the system to whoever provoked the failure",
			Rationale:            "errorhandler renders internal failure detail into the response",
			ConfigurationEnabled: true,
		},
		{
			// Serving an index means publishing the file NAMES, which is a map of
			// everything in the directory including whatever was left there.
			ID: "directory-listing", Symbol: "serve-index", Always: true,
			CWE:       "CWE-548",
			Finding:   "Directory listing served",
			Reason:    "publishing the file names in a directory publishes a map of everything in it, including whatever was left there by accident",
			Rationale: "serve-index generates a listing for a directory",
		},
		{
			ID: "directory-listing", Symbol: "serve-index.default", Always: true,
			CWE:       "CWE-548",
			Finding:   "Directory listing served",
			Reason:    "publishing the file names in a directory publishes a map of everything in it, including whatever was left there by accident",
			Rationale: "serve-index generates a listing for a directory",
		},

		{
			// Superseded and dangerous in a way its replacement is not: createCipher
			// derives the key from the password with a single unsalted MD5, so two
			// applications with the same passphrase get the same key. Node removed it.
			ID: "obsolete-function", Symbol: "crypto.createCipher", Always: true,
			CWE:       "CWE-477",
			Finding:   "Obsolete function",
			Reason:    "createCipher derives its key with a single unsalted MD5 of the passphrase, which is why it was deprecated and then removed",
			Rationale: "createCipher() is superseded by createCipheriv()",
		},
		{
			ID: "obsolete-function", Symbol: "crypto.createDecipher", Always: true,
			CWE:       "CWE-477",
			Finding:   "Obsolete function",
			Reason:    "createDecipher derives its key with a single unsalted MD5 of the passphrase, which is why it was deprecated and then removed",
			Rationale: "createDecipher() is superseded by createDecipheriv()",
		},
		{
			// RSA without OAEP. PKCS#1 v1.5 encryption padding has been known broken
			// since 1998 and the fix is a different padding, not a different key.
			ID: "rsa-without-oaep", Symbol: "Crypto.Cipher.PKCS1_v1_5.new", Always: true,
			CWE:       "CWE-780",
			Finding:   "RSA used without OAEP padding",
			Reason:    "PKCS#1 v1.5 encryption padding is vulnerable to an adaptive chosen-ciphertext attack that recovers the plaintext, and OAEP is the padding that is not",
			Rationale: "PKCS1_v1_5 is the padding without OAEP",
		},
		{
			ID: "rsa-without-oaep", Symbol: "Cryptodome.Cipher.PKCS1_v1_5.new", Always: true,
			CWE:       "CWE-780",
			Finding:   "RSA used without OAEP padding",
			Reason:    "PKCS#1 v1.5 encryption padding is vulnerable to an adaptive chosen-ciphertext attack that recovers the plaintext, and OAEP is the padding that is not",
			Rationale: "PKCS1_v1_5 is the padding without OAEP",
		},

		// --- request validation -----------------------------------------------------
		//
		// The other half of CWE-1333, and the half a flow analysis cannot reach. A route
		// that validates its request with a schema never writes the match: it writes the
		// PATTERN, hands the schema to whatever parses the request, and the string and the
		// pattern meet somewhere inside the validation library. There is no call in the
		// application where the two are arguments to each other, so there is nothing for a
		// channel to fire on -- and this is how a modern application spells its input
		// validation, which is precisely where a pattern meets a caller's string first.
		//
		// So the evidence is the schema and the surface. `z.string().regex(P)` says that P
		// will be run against whatever this schema is given; the schema being built in a
		// function an enumerated entry point reaches says who gives it one. Both halves are
		// written down, neither is guessed, and the pattern still has to be one the
		// structural test calls catastrophic.
		//
		// umami's pre-authentication ReDoS is exactly this: `domain:
		// z.string().trim().regex(DOMAIN_REGEX).max(500)` in the POST handler, validated by
		// a shared helper that runs the schema before it checks any credential.
		{
			ID: "catastrophic-pattern-in-schema", Method: "regex",
			SymbolContains: []string{"z.string", "zod.string", "z.coerce.string", "z.custom"},
			PatternArg:     at(0), EntryReachable: true,
			CWE:       "CWE-1333",
			Finding:   "A route's input schema validates with a pattern that can be made to churn",
			Reason:    "the schema runs this pattern against whatever the route is sent, and the pattern can be made to backtrack exponentially, so a long string a caller chooses stops the process without touching it",
			Rationale: "the schema field is validated with a pattern that has two repetitions able to claim the same input",
		},
		{
			// Joi and yup spell the same field the same way under different names.
			ID: "catastrophic-pattern-in-schema", Method: "pattern",
			SymbolContains: []string{"Joi.string", "joi.string"},
			PatternArg:     at(0), EntryReachable: true,
			CWE:       "CWE-1333",
			Finding:   "A route's input schema validates with a pattern that can be made to churn",
			Reason:    "the schema runs this pattern against whatever the route is sent, and the pattern can be made to backtrack exponentially, so a long string a caller chooses stops the process without touching it",
			Rationale: "the schema field is validated with a pattern that has two repetitions able to claim the same input",
		},
		{
			ID: "catastrophic-pattern-in-schema", Method: "matches",
			SymbolContains: []string{"yup.string", "y.string"},
			PatternArg:     at(0), EntryReachable: true,
			CWE:       "CWE-1333",
			Finding:   "A route's input schema validates with a pattern that can be made to churn",
			Reason:    "the schema runs this pattern against whatever the route is sent, and the pattern can be made to backtrack exponentially, so a long string a caller chooses stops the process without touching it",
			Rationale: "the schema field is validated with a pattern that has two repetitions able to claim the same input",
		},

		// --- files and permissions --------------------------------------------------
		{
			// mktemp returns a NAME and does not create the file, so between the name
			// being chosen and the program opening it, anything else can create it first
			// -- as a symlink to somewhere the program can write and the attacker cannot.
			// Python's own documentation says not to use it. There is no safe way to call
			// it, which is why this matches the call itself.
			ID: "insecure-temp-file", Symbol: "tempfile.mktemp", Always: true,
			CWE:       "CWE-378",
			Finding:   "Temporary file created by name rather than by handle",
			Reason:    "mktemp() hands back a name without creating anything, so another process can win the race and put its own file, or a symlink, there first",
			Rationale: "mktemp() is documented as unsafe and superseded by mkstemp() and NamedTemporaryFile()",
		},
		{
			// The mode is wrong because of a BIT, not because of a number.
			ID: "world-writable", Symbol: "os.chmod", ArgIndex: 1, MaskedBits: atLeast(0o002),
			CWE:       "CWE-276",
			Finding:   "File left writable by everyone",
			Reason:    "a mode that grants write to others lets any account on the host change the file, which for anything the application later reads or executes is a way in",
			Rationale: "the second argument to chmod() is the mode",
		},
		{
			ID: "world-writable", Symbol: "os.fchmod", ArgIndex: 1, MaskedBits: atLeast(0o002),
			CWE:       "CWE-276",
			Finding:   "File left writable by everyone",
			Reason:    "a mode that grants write to others lets any account on the host change the file, which for anything the application later reads or executes is a way in",
			Rationale: "the second argument to fchmod() is the mode",
		},
		{
			ID: "world-writable", Symbol: "fs.chmod", ArgIndex: 1, MaskedBits: atLeast(0o002),
			CWE:       "CWE-276",
			Finding:   "File left writable by everyone",
			Reason:    "a mode that grants write to others lets any account on the host change the file, which for anything the application later reads or executes is a way in",
			Rationale: "the second argument to chmod() is the mode",
		},
		{
			ID: "world-writable", Symbol: "fs.chmodSync", ArgIndex: 1, MaskedBits: atLeast(0o002),
			CWE:       "CWE-276",
			Finding:   "File left writable by everyone",
			Reason:    "a mode that grants write to others lets any account on the host change the file, which for anything the application later reads or executes is a way in",
			Rationale: "the second argument to chmodSync() is the mode",
		},
		{
			ID: "world-writable", Symbol: "os.mkdir", ArgIndex: 1, MaskedBits: atLeast(0o002),
			CWE:       "CWE-276",
			Finding:   "Directory left writable by everyone",
			Reason:    "a directory anyone may write to lets any account on the host add, replace or remove what the application will later read",
			Rationale: "the second argument to mkdir() is the mode",
		},
		{
			ID: "world-writable", Symbol: "os.makedirs", ArgIndex: 1, MaskedBits: atLeast(0o002),
			CWE:       "CWE-276",
			Finding:   "Directory left writable by everyone",
			Reason:    "a directory anyone may write to lets any account on the host add, replace or remove what the application will later read",
			Rationale: "the second argument to makedirs() is the mode",
		},

		// --- key derivation and IVs -------------------------------------------------
		// A work factor is wrong for a reason no list of forbidden strings can express,
		// so these are thresholds. The numbers are the floors below which the parameter
		// is doing no work worth the name, not the values anybody should ship: bcrypt at
		// 10 is the library default, and PBKDF2 guidance has been climbing for a decade
		// and is far above 100,000 now. Being at the floor is not a finding, because a
		// rule that fires on current guidance would fire on every codebase forever and
		// be turned off within the week.
		{
			ID: "weak-password-hash", Symbol: "bcrypt.hash", ArgIndex: 1, BelowValue: atLeast(10),
			CWE:          "CWE-916",
			Finding:      "Password hash with too little work",
			Reason:       "a password hash is only as good as the time it costs to compute, and below this the cost is small enough that guessing the whole password space is practical",
			DependsOnUse: "a work factor is only too low for a LOW-ENTROPY input, and the call does not say what it was given: lnbits derives a key from an already-random 32-byte secret with 2048 iterations, which is fine, and reads identically to hashing a password with 2048 iterations, which is not",
			Rationale:    "the second argument to hash() is the cost factor",
		},
		{
			ID: "weak-password-hash", Symbol: "bcrypt.hashSync", ArgIndex: 1, BelowValue: atLeast(10),
			CWE:          "CWE-916",
			Finding:      "Password hash with too little work",
			Reason:       "a password hash is only as good as the time it costs to compute, and below this the cost is small enough that guessing the whole password space is practical",
			DependsOnUse: "a work factor is only too low for a LOW-ENTROPY input, and the call does not say what it was given: lnbits derives a key from an already-random 32-byte secret with 2048 iterations, which is fine, and reads identically to hashing a password with 2048 iterations, which is not",
			Rationale:    "the second argument to hashSync() is the cost factor",
		},
		{
			ID: "weak-password-hash", Symbol: "bcrypt.genSalt", ArgIndex: 0, BelowValue: atLeast(10),
			CWE:          "CWE-916",
			Finding:      "Password hash with too little work",
			Reason:       "a password hash is only as good as the time it costs to compute, and below this the cost is small enough that guessing the whole password space is practical",
			DependsOnUse: "a work factor is only too low for a LOW-ENTROPY input, and the call does not say what it was given: lnbits derives a key from an already-random 32-byte secret with 2048 iterations, which is fine, and reads identically to hashing a password with 2048 iterations, which is not",
			Rationale:    "genSalt() is given the cost factor",
		},
		{
			ID: "weak-password-hash", Symbol: "bcrypt.genSaltSync", ArgIndex: 0, BelowValue: atLeast(10),
			CWE:          "CWE-916",
			Finding:      "Password hash with too little work",
			Reason:       "a password hash is only as good as the time it costs to compute, and below this the cost is small enough that guessing the whole password space is practical",
			DependsOnUse: "a work factor is only too low for a LOW-ENTROPY input, and the call does not say what it was given: lnbits derives a key from an already-random 32-byte secret with 2048 iterations, which is fine, and reads identically to hashing a password with 2048 iterations, which is not",
			Rationale:    "genSaltSync() is given the cost factor",
		},
		{
			ID: "weak-password-hash", Symbol: "crypto.pbkdf2", ArgIndex: 2, BelowValue: atLeast(100000),
			CWE:          "CWE-916",
			Finding:      "Password hash with too little work",
			Reason:       "a password hash is only as good as the time it costs to compute, and below this the cost is small enough that guessing the whole password space is practical",
			DependsOnUse: "a work factor is only too low for a LOW-ENTROPY input, and the call does not say what it was given: lnbits derives a key from an already-random 32-byte secret with 2048 iterations, which is fine, and reads identically to hashing a password with 2048 iterations, which is not",
			Rationale:    "the third argument to pbkdf2() is the iteration count",
		},
		{
			ID: "weak-password-hash", Symbol: "crypto.pbkdf2Sync", ArgIndex: 2, BelowValue: atLeast(100000),
			CWE:          "CWE-916",
			Finding:      "Password hash with too little work",
			Reason:       "a password hash is only as good as the time it costs to compute, and below this the cost is small enough that guessing the whole password space is practical",
			DependsOnUse: "a work factor is only too low for a LOW-ENTROPY input, and the call does not say what it was given: lnbits derives a key from an already-random 32-byte secret with 2048 iterations, which is fine, and reads identically to hashing a password with 2048 iterations, which is not",
			Rationale:    "the third argument to pbkdf2Sync() is the iteration count",
		},
		{
			ID: "weak-password-hash", Symbol: "hashlib.pbkdf2_hmac", ArgIndex: 3, BelowValue: atLeast(100000),
			CWE:          "CWE-916",
			Finding:      "Password hash with too little work",
			Reason:       "a password hash is only as good as the time it costs to compute, and below this the cost is small enough that guessing the whole password space is practical",
			DependsOnUse: "a work factor is only too low for a LOW-ENTROPY input, and the call does not say what it was given: lnbits derives a key from an already-random 32-byte secret with 2048 iterations, which is fine, and reads identically to hashing a password with 2048 iterations, which is not",
			Rationale:    "the fourth argument to pbkdf2_hmac() is the iteration count",
		},
		{
			// Becoming root, or staying root. A process that runs as uid 0 does everything
			// as uid 0, so any defect anywhere in it is a defect with the whole machine
			// behind it.
			ID: "unnecessary-privilege", Symbol: "os.setuid", ArgIndex: 0, Disallowed: []string{"0"},
			CWE:       "CWE-250",
			Finding:   "Process takes root privileges",
			Reason:    "a process running as root does everything as root, so any defect anywhere in it is a defect with the whole machine behind it",
			Rationale: "setuid(0) is a request for the superuser",
		},
		{
			ID: "unnecessary-privilege", Symbol: "os.seteuid", ArgIndex: 0, Disallowed: []string{"0"},
			CWE:       "CWE-250",
			Finding:   "Process takes root privileges",
			Reason:    "a process running as root does everything as root, so any defect anywhere in it is a defect with the whole machine behind it",
			Rationale: "seteuid(0) is a request for the superuser",
		},
		{
			ID: "unnecessary-privilege", Symbol: "process.setuid", ArgIndex: 0, Disallowed: []string{"0", "root"},
			CWE:       "CWE-250",
			Finding:   "Process takes root privileges",
			Reason:    "a process running as root does everything as root, so any defect anywhere in it is a defect with the whole machine behind it",
			Rationale: "setuid(0) is a request for the superuser",
		},

		{
			// The lenient parser exists for peers that send malformed requests, and
			// leniency is exactly what request smuggling needs: two parsers in a chain
			// disagreeing about where one request ends and the next begins.
			ID: "lenient-http-parser", AnyCall: true, Keyword: "insecureHTTPParser",
			Disallowed: []string{"true"},
			CWE:        "CWE-444",
			Finding:    "Lenient HTTP parser enabled",
			Reason:     "a parser that accepts malformed requests can disagree with the proxy in front of it about where one request ends, which is what lets a caller smuggle a second one",
			Rationale:  "the server is configured to accept malformed requests",
		},

		{
			// Serving a directory that was never meant to be public. `express.static(".")`
			// hands over the whole project: the .env file, the .git directory, the
			// backups somebody left in the root, the source itself.
			// The same handler told to serve the files a directory listing would hide.
			// `.env`, `.git` and `.npmrc` are dotfiles, and serving them is serving the
			// credentials in them.
			ID: "world-readable-root", Symbol: "express.static", Keyword: "dotfiles",
			Disallowed: []string{"allow"},
			CWE:        "CWE-552",
			Finding:    "A directory served whole to anyone who asks",
			Reason:     "the files this option un-hides are the ones that hold credentials: the environment file, the version control directory, the package registry token",
			Rationale:  "dotfiles are served rather than ignored",
		},
		{
			ID: "world-readable-root", Symbol: "express.static", ArgIndex: 0,
			Disallowed: []string{".", "./", "/", "..", "../", "/home", "/etc", "/root", "/var"},
			CWE:        "CWE-552",
			Finding:    "A directory served whole to anyone who asks",
			Reason:     "everything under this path becomes fetchable by URL, and a project root holds the environment file, the version control directory and whatever was left there",
			Rationale:  "the first argument is the directory being served",
		},
		{
			ID: "world-readable-root", Symbol: "flask.send_from_directory", ArgIndex: 0,
			Disallowed: []string{".", "./", "/", "..", "../", "/home", "/etc", "/root", "/var"},
			CWE:        "CWE-552",
			Finding:    "A directory served whole to anyone who asks",
			Reason:     "everything under this path becomes fetchable by URL, and a project root holds the environment file, the version control directory and whatever was left there",
			Rationale:  "the first argument is the directory being served from",
		},
		{
			// A salt written into the source is the same salt for every password in the
			// database, which is what a salt exists to prevent: one precomputed table
			// then works against all of them at once.
			ID: "predictable-salt", Symbol: "crypto.pbkdf2", ArgIndex: 1, AnyLiteral: true,
			CWE:       "CWE-760",
			Finding:   "Password hashed with a salt written into the source",
			Reason:    "a salt that is the same for every password is not doing the one thing a salt does, which is to make a precomputed table useless",
			Rationale: "the second argument to pbkdf2() is the salt",
		},
		{
			ID: "predictable-salt", Symbol: "crypto.pbkdf2Sync", ArgIndex: 1, AnyLiteral: true,
			CWE:       "CWE-760",
			Finding:   "Password hashed with a salt written into the source",
			Reason:    "a salt that is the same for every password is not doing the one thing a salt does, which is to make a precomputed table useless",
			Rationale: "the second argument to pbkdf2Sync() is the salt",
		},
		{
			ID: "predictable-salt", Symbol: "hashlib.pbkdf2_hmac", ArgIndex: 2, AnyLiteral: true,
			CWE:       "CWE-760",
			Finding:   "Password hashed with a salt written into the source",
			Reason:    "a salt that is the same for every password is not doing the one thing a salt does, which is to make a precomputed table useless",
			Rationale: "the third argument to pbkdf2_hmac() is the salt",
		},
		{
			// A credential cookie good for a year is a stolen credential good for a year.
			// Nothing says what a reasonable session lifetime is, but thirty days is well
			// past the point where the answer stops being "it depends" -- and the
			// attribute is only asked about for cookies that carry a credential, because
			// a year-long theme preference is a feature.
			//
			// Express counts MILLISECONDS.
			ID: "long-lived-session", Method: "cookie", Keyword: "maxAge", AboveValue: atMost(2592000000),
			Qualifiers: credentialCookie,
			CWE:        "CWE-613",
			Finding:    "Session cookie valid for longer than a month",
			Reason:     "a credential that stays valid for a year is a credential an attacker who steals it keeps for a year, and nothing the user does afterwards takes it back",
			Rationale:  "maxAge is how long the browser keeps sending this cookie, in milliseconds",
		},
		{
			// A bearer token with no expiry at all. Whoever holds it holds it forever:
			// there is no revocation in a signed token, so the only thing that ends one is
			// the clock, and this one has no clock.
			//
			// An ABSENCE rule, so it only speaks where every place an expiry can be written
			// was enumerated. An inline payload with no `exp` makes an omitted options
			// argument knowable; a payload built elsewhere does not.
			ID: "unexpiring-token", Symbol: "jsonwebtoken.sign",
			RequiredKeyword: "expiresIn", RequiredAnyOf: []string{"expiresIn", "exp"},
			OptionsArg: 2, AlsoEnumerated: []int{0}, ExcludeTestModule: true,
			CWE:       "CWE-613",
			Finding:   "Signed token issued with no expiry",
			Reason:    "a signed token carries no revocation of its own, so unless the server keeps state to check it against, the only thing that ends one is its expiry",
			Rationale: "the options argument to sign() enumerates its keys and expiresIn is not among them",
		},
		{
			// A tar member can be a SYMLINK, and extracting one writes through it to
			// wherever it points. The `..` member is the traversal everybody knows about
			// and is claimed under CWE-22; this is the other half, and the same one
			// parameter settles both. Python added `filter=` for exactly this reason and
			// is making `filter="data"` the default, which is as clear a statement as a
			// language ever makes that the old call was wrong.
			//
			// An ABSENCE rule, so it speaks only where the keywords were enumerated: a
			// call whose options came from somewhere else is unknowable and is passed
			// over in silence. Zipfile is deliberately not here -- it has no such
			// parameter, and its members are already judged by where the archive came
			// from.
			// OptionsArg -1: a Python call keeps its options in its KEYWORDS, and the
			// frontend marks that group enumerated whenever no `**kwargs` hides a key.
			ID: "unfiltered-extraction", Method: "extractall",
			ReceiverFromCall: []string{"tarfile.open", "tarfile.TarFile", "TarFile"},
			RequiredKeyword:  "filter", OptionsArg: -1,
			CWE:       "CWE-59",
			Finding:   "Archive extracted without a member filter",
			Reason:    "a member of a tar archive can be a symbolic link, and extracting one writes through it to wherever it points -- outside the directory the program chose",
			Rationale: "extractall() is called without the filter that decides what a member may be",
		},
		{
			// Flask counts SECONDS. Same keyword, different unit, which is why the
			// threshold lives on the rule rather than on the name.
			ID: "long-lived-session", Method: "set_cookie", Keyword: "max_age", AboveValue: atMost(2592000),
			Qualifiers: credentialCookie,
			CWE:        "CWE-613",
			Finding:    "Session cookie valid for longer than a month",
			Reason:     "a credential that stays valid for a year is a credential an attacker who steals it keeps for a year, and nothing the user does afterwards takes it back",
			Rationale:  "max_age is how long the browser keeps sending this cookie, in seconds",
		},

		{
			// A link or a script that opens a new window hands the opened page a live
			// reference back to this one through `window.opener`, and the opened page can
			// use it to navigate this one somewhere else. The third argument is where
			// `noopener` would have gone, and it is not there.
			// The features string is there and does not say noopener, which is the same
			// omission written a different way.
			ID: "opener-reachable", Symbol: "window.open", ArgIndex: 2, Always: true,
			ExternalDestinationArg: at(0),
			Qualifiers: []ArgCondition{
				{ArgIndex: 1, Substring: true, AnyOf: []string{"_blank", "blank"}},
				{ArgIndex: 2, Substring: true, NoneOf: []string{"noopener"}},
			},
			CWE:       "CWE-1022",
			Finding:   "A new window left holding a reference back to this one",
			Reason:    "the opened page can navigate the page that opened it, which is how a link to somewhere else replaces the page behind it with a copy that asks for a password",
			Rationale: "the features argument is written and does not include noopener",
		},
		{
			ID: "opener-reachable", Symbol: "window.open", MissingArg: atLeast(2),
			ExternalDestinationArg: at(0),
			Qualifiers:             []ArgCondition{{ArgIndex: 1, Substring: true, AnyOf: []string{"_blank", "blank"}}},
			CWE:                    "CWE-1022",
			Finding:                "A new window left holding a reference back to this one",
			Reason:                 "the opened page can navigate the page that opened it, which is how a link to somewhere else replaces the page behind it with a copy that asks for a password",
			Rationale:              "the third argument is where noopener would be, and the call has no third argument",
		},

		{
			// Code fetched over the network and run without anybody checking WHAT was
			// fetched. Whoever can answer for that host, or sit between here and it,
			// chooses what this machine executes -- and a redirect, an expired domain or a
			// compromised mirror is enough. There is no signature to verify because
			// nothing was signed.
			ID: "unverified-download", Symbol: "child_process.exec", ArgIndex: 0, Always: true,
			Qualifiers: []ArgCondition{
				{ArgIndex: 0, Substring: true, AnyOf: []string{"curl ", "wget ", "iwr ", "invoke-webrequest"}},
				{ArgIndex: 0, Substring: true, AnyOf: []string{"| sh", "|sh", "| bash", "|bash", "| python", "|python", "| ruby", "|ruby"}},
			},
			CWE:       "CWE-494",
			Finding:   "Code downloaded and run without an integrity check",
			Reason:    "what gets executed is whatever the host answered with, and nothing here checks that it is what was expected",
			Rationale: "the command fetches something over the network and pipes it into an interpreter",
		},
		{
			// Code fetched over the network and run without anybody checking WHAT was
			// fetched. Whoever can answer for that host, or sit between here and it,
			// chooses what this machine executes -- and a redirect, an expired domain or a
			// compromised mirror is enough. There is no signature to verify because
			// nothing was signed.
			ID: "unverified-download", Symbol: "child_process.execSync", ArgIndex: 0, Always: true,
			Qualifiers: []ArgCondition{
				{ArgIndex: 0, Substring: true, AnyOf: []string{"curl ", "wget ", "iwr ", "invoke-webrequest"}},
				{ArgIndex: 0, Substring: true, AnyOf: []string{"| sh", "|sh", "| bash", "|bash", "| python", "|python", "| ruby", "|ruby"}},
			},
			CWE:       "CWE-494",
			Finding:   "Code downloaded and run without an integrity check",
			Reason:    "what gets executed is whatever the host answered with, and nothing here checks that it is what was expected",
			Rationale: "the command fetches something over the network and pipes it into an interpreter",
		},
		{
			// Code fetched over the network and run without anybody checking WHAT was
			// fetched. Whoever can answer for that host, or sit between here and it,
			// chooses what this machine executes -- and a redirect, an expired domain or a
			// compromised mirror is enough. There is no signature to verify because
			// nothing was signed.
			ID: "unverified-download", Symbol: "os.system", ArgIndex: 0, Always: true,
			Qualifiers: []ArgCondition{
				{ArgIndex: 0, Substring: true, AnyOf: []string{"curl ", "wget ", "iwr ", "invoke-webrequest"}},
				{ArgIndex: 0, Substring: true, AnyOf: []string{"| sh", "|sh", "| bash", "|bash", "| python", "|python", "| ruby", "|ruby"}},
			},
			CWE:       "CWE-494",
			Finding:   "Code downloaded and run without an integrity check",
			Reason:    "what gets executed is whatever the host answered with, and nothing here checks that it is what was expected",
			Rationale: "the command fetches something over the network and pipes it into an interpreter",
		},
		{
			// Code fetched over the network and run without anybody checking WHAT was
			// fetched. Whoever can answer for that host, or sit between here and it,
			// chooses what this machine executes -- and a redirect, an expired domain or a
			// compromised mirror is enough. There is no signature to verify because
			// nothing was signed.
			ID: "unverified-download", Symbol: "subprocess.getstatusoutput", ArgIndex: 0, Always: true,
			Qualifiers: []ArgCondition{
				{ArgIndex: 0, Substring: true, AnyOf: []string{"curl ", "wget ", "iwr ", "invoke-webrequest"}},
				{ArgIndex: 0, Substring: true, AnyOf: []string{"| sh", "|sh", "| bash", "|bash", "| python", "|python", "| ruby", "|ruby"}},
			},
			CWE:       "CWE-494",
			Finding:   "Code downloaded and run without an integrity check",
			Reason:    "what gets executed is whatever the host answered with, and nothing here checks that it is what was expected",
			Rationale: "the command fetches something over the network and pipes it into an interpreter",
		},

		{
			// An XML parser told to lift its own limits. A document a few kilobytes long
			// can then expand into gigabytes -- the same nested-entity trick that has had
			// a name for twenty years -- and the process dies holding whatever else it
			// was doing.
			ID: "entity-expansion", Symbol: "lxml.etree.XMLParser", Keyword: "huge_tree",
			Disallowed: []string{"true"},
			CWE:        "CWE-776",
			Finding:    "XML parser told to lift its expansion limits",
			Reason:     "the limits being lifted are the ones that stop a small document from expanding into a large one, which is the whole of the attack",
			Rationale:  "huge_tree removes libxml2's own guard against runaway entity expansion",
		},
		{
			ID: "entity-expansion", Symbol: "lxml.etree.iterparse", Keyword: "huge_tree",
			Disallowed: []string{"true"},
			CWE:        "CWE-776",
			Finding:    "XML parser told to lift its expansion limits",
			Reason:     "the limits being lifted are the ones that stop a small document from expanding into a large one, which is the whole of the attack",
			Rationale:  "huge_tree removes libxml2's own guard against runaway entity expansion",
		},
		{
			ID: "entity-expansion", Symbol: "lxml.etree.ETCompatXMLParser", Keyword: "huge_tree",
			Disallowed: []string{"true"},
			CWE:        "CWE-776",
			Finding:    "XML parser told to lift its expansion limits",
			Reason:     "the limits being lifted are the ones that stop a small document from expanding into a large one, which is the whole of the attack",
			Rationale:  "huge_tree removes libxml2's own guard against runaway entity expansion",
		},

		{
			// The renderer given the whole runtime. With node integration on, anything
			// that ends up as script in the page -- a remote resource, a rendered
			// message, an injected string -- has the filesystem and the process API,
			// which turns every cross-site scripting bug in the page into code execution
			// on the machine.
			ID: "renderer-has-runtime", AnyCall: true, Keyword: "nodeIntegration",
			Disallowed: []string{"true"},
			CWE:        "CWE-749",
			Finding:    "Dangerous runtime exposed to page content",
			Reason:     "page content gets the filesystem and the process API, so anything that becomes script in this window becomes code running on the machine",
			Rationale:  "node integration is switched on in the window's options",
		},
		{
			ID: "renderer-has-runtime", AnyCall: true, Keyword: "contextIsolation",
			Disallowed: []string{"false"},
			CWE:        "CWE-749",
			Finding:    "Dangerous runtime exposed to page content",
			Reason:     "without isolation the preload script and the page share one context, so anything the preload exposed is reachable from the page itself",
			Rationale:  "context isolation is switched off in the window's options",
		},
		{
			ID: "renderer-has-runtime", AnyCall: true, Keyword: "nodeIntegrationInWorker",
			Disallowed: []string{"true"},
			CWE:        "CWE-749",
			Finding:    "Dangerous runtime exposed to page content",
			Reason:     "a worker started by the page gets the filesystem and the process API, which is the same exposure at one remove",
			Rationale:  "node integration is switched on for the window's workers",
		},
		{
			ID: "renderer-has-runtime", AnyCall: true, Keyword: "nodeIntegrationInSubFrames",
			Disallowed: []string{"true"},
			CWE:        "CWE-749",
			Finding:    "Dangerous runtime exposed to page content",
			Reason:     "a frame the page embeds gets the filesystem and the process API, and the page chooses what it embeds",
			Rationale:  "node integration is switched on for the window's subframes",
		},
		{
			ID: "renderer-has-runtime", AnyCall: true, Keyword: "enableRemoteModule",
			Disallowed: []string{"true"},
			CWE:        "CWE-749",
			Finding:    "Dangerous runtime exposed to page content",
			Reason:     "the remote module hands the page a live reference to objects in the privileged process",
			Rationale:  "the remote module is enabled in the window's options",
		},

		{
			// Radix zero asks the parser to GUESS the base from the text: `0x10` parses
			// as sixteen, so two strings the caller may send mean one number and one of
			// them was not supposed to be accepted. Every place this matters -- a port, an
			// address octet, a quantity, an identifier -- the caller writes the text and
			// the parser picks the base.
			//
			// The leading-zero octal reading is NOT part of this. ES5 removed it and
			// `parseInt("010", 0)` is ten in any runtime written this century; saying
			// otherwise would be a rule justified by a fact that stopped being true.
			ID: "inferred-radix", Symbol: "Number.parseInt", ArgIndex: 1,
			Disallowed: []string{"0"},
			CWE:        "CWE-1389",
			Finding:    "Number parsed with the base left to the text",
			Reason:     "radix zero lets the input choose the base, so a caller who sends 0x10 gets sixteen from a field that was meant to hold ten",
			Rationale:  "the second argument to parseInt() is the radix, and zero means infer it",
		},
		{
			ID: "inferred-radix", Symbol: "parseInt", ArgIndex: 1,
			Disallowed: []string{"0"},
			CWE:        "CWE-1389",
			Finding:    "Number parsed with the base left to the text",
			Reason:     "radix zero lets the input choose the base, so a caller who sends 0x10 gets sixteen from a field that was meant to hold ten",
			Rationale:  "the second argument to parseInt() is the radix, and zero means infer it",
		},

		{
			// A server told to accept connections on every interface it has. On a laptop
			// that is a demo; on a host with a second network card, a container with a
			// host-network mode, or a cloud instance with a public address, it is the
			// difference between a service the application can reach and a service
			// anybody can.
			ID: "bound-to-every-interface", Method: "run", Keyword: "host",
			Disallowed: []string{"0.0.0.0", "::", "[::]"},
			CWE:        "CWE-1327",
			Finding:    "Server bound to every interface",
			Reason:     "the listener accepts connections on every address the host has, which on anything but a laptop includes ones the application was never meant to be reachable from",
			Rationale:  "the host option names the address to listen on, and this one means all of them",
		},
		{
			ID: "bound-to-every-interface", Symbol: "uvicorn.run", Keyword: "host",
			Disallowed: []string{"0.0.0.0", "::", "[::]"},
			CWE:        "CWE-1327",
			Finding:    "Server bound to every interface",
			Reason:     "the listener accepts connections on every address the host has, which on anything but a laptop includes ones the application was never meant to be reachable from",
			Rationale:  "the host option names the address to listen on, and this one means all of them",
		},
		{
			ID: "bound-to-every-interface", Symbol: "waitress.serve", Keyword: "host",
			Disallowed: []string{"0.0.0.0", "::", "[::]"},
			CWE:        "CWE-1327",
			Finding:    "Server bound to every interface",
			Reason:     "the listener accepts connections on every address the host has, which on anything but a laptop includes ones the application was never meant to be reachable from",
			Rationale:  "the host option names the address to listen on, and this one means all of them",
		},
		{
			// Node puts the address in the second POSITION rather than in an option.
			// Node also accepts the options object form.
			ID: "bound-to-every-interface", Method: "listen", Keyword: "host",
			Disallowed: []string{"0.0.0.0", "::", "[::]"},
			CWE:        "CWE-1327",
			Finding:    "Server bound to every interface",
			Reason:     "the listener accepts connections on every address the host has, which on anything but a laptop includes ones the application was never meant to be reachable from",
			Rationale:  "the host option names the address to listen on, and this one means all of them",
		},
		{
			ID: "bound-to-every-interface", Method: "listen", ArgIndex: 1,
			Disallowed: []string{"0.0.0.0", "::", "[::]"},
			CWE:        "CWE-1327",
			Finding:    "Server bound to every interface",
			Reason:     "the listener accepts connections on every address the host has, which on anything but a laptop includes ones the application was never meant to be reachable from",
			Rationale:  "the second argument to listen() is the address to bind, and this one means all of them",
		},

		{
			// One initialisation vector for the whole process. It must be different for
			// every message; bound at module scope it is computed once when the file
			// loads, which is different for every PROCESS -- not the same thing, and it
			// looks right at a glance because a random number was involved.
			//
			// Two messages encrypted under one key and one IV leak the XOR of their
			// plaintexts, and in counter mode they leak it outright.
			ID: "reused-iv", Symbol: "crypto.createCipheriv", ArgFromModuleScope: arg(2),
			CWE:       "CWE-323",
			Finding:   "One initialisation vector for every message",
			Reason:    "an initialisation vector bound at module scope is computed once and reused for every message the process encrypts, which is the one thing it must never be",
			Rationale: "the third argument is the initialisation vector, and it is bound where the file loads rather than where the message is",
		},
		{
			// One initialisation vector for the whole process. It must be different for
			// every message; bound at module scope it is computed once when the file
			// loads, which is different for every PROCESS -- not the same thing, and it
			// looks right at a glance because a random number was involved.
			//
			// Two messages encrypted under one key and one IV leak the XOR of their
			// plaintexts, and in counter mode they leak it outright.
			ID: "reused-iv", Symbol: "crypto.createDecipheriv", ArgFromModuleScope: arg(2),
			CWE:       "CWE-323",
			Finding:   "One initialisation vector for every message",
			Reason:    "an initialisation vector bound at module scope is computed once and reused for every message the process encrypts, which is the one thing it must never be",
			Rationale: "the third argument is the initialisation vector, and it is bound where the file loads rather than where the message is",
		},

		{
			// Turning off the header that stops the page being framed. Clickjacking is
			// the caller's page wrapping yours and collecting the clicks.
			ID: "frames-allowed", AnyCall: true, Keyword: "xFrameOptions",
			Disallowed: []string{"false"},
			CWE:        "CWE-1021",
			Finding:    "Framing protection switched off",
			Reason:     "without a frame restriction another site can load this page invisibly over its own and collect the clicks meant for it",
			Rationale:  "the frame-options header is disabled in the call",
		},
		{
			ID: "frames-allowed", AnyCall: true, Keyword: "frameguard",
			Disallowed: []string{"false"},
			CWE:        "CWE-1021",
			Finding:    "Framing protection switched off",
			Reason:     "without a frame restriction another site can load this page invisibly over its own and collect the clicks meant for it",
			Rationale:  "the frame-options header is disabled in the call",
		},

		{
			// An initialisation vector must be unpredictable and must not repeat. Written
			// into the source it is both predictable and reused on every single message,
			// which for CBC leaks whether two plaintexts start alike and for CTR is
			// catastrophic. Matched on having been WRITTEN DOWN, exactly as a hardcoded
			// key is: what it says does not matter.
			//
			// What it says does not matter; what the MODE says does. The third slot holds
			// an IV in CBC, CTR, GCM, CFB and OFB and holds nothing in ECB, which has no
			// IV at all -- Node still requires the argument and an empty string is the
			// ordinary way to write it. Reading the third argument without the first
			// judged an argument whose meaning had not been established, and reported
			// `createCipheriv("DES-ECB", key, "")` as a predictable IV. The true statement
			// about that same line -- single-DES in ECB -- is already emitted by
			// `weak-cipher` off argument zero, so this was duplication as well as error.
			ID: "predictable-iv", Symbol: "crypto.createCipheriv", ArgIndex: 2, AnyLiteral: true,
			Qualifiers: []ArgCondition{
				{ArgIndex: 2, NoneOf: []string{"null", "undefined"}},
				{ArgIndex: 0, NoneOf: []string{"ecb"}, HoldsWhenUnread: true},
			},
			CWE:       "CWE-329",
			Finding:   "Initialisation vector written into the source",
			Reason:    "an IV must be unpredictable and must never repeat, and one written down is both predictable and reused on every message",
			Rationale: "the third argument to createCipheriv() is the IV",
		},

		// --- cookie attributes ------------------------------------------------------
		// Two shapes per weakness, because the two ecosystems spell options differently
		// and the difference is real: JavaScript passes an object, Python passes keyword
		// arguments. Both end up in the same keyword slots, which is the seam doing its
		// job (ADR-001).
		{
			ID: "cookie-not-http-only", Method: "cookie", ArgIndex: -1, Qualifiers: credentialCookie,
			RequiredKeyword: "httpOnly", OptionsArg: 2,
			CWE:       "CWE-1004",
			Finding:   "Session cookie readable by script",
			Reason:    "a cookie that carries a credential must not be readable by script, or any cross-site scripting anywhere on the origin becomes account takeover",
			Rationale: "res.cookie() sets no httpOnly attribute",
		},
		{
			ID: "cookie-not-http-only", Method: "set_cookie", ArgIndex: -1, Qualifiers: credentialCookie,
			RequiredKeyword: "httponly", OptionsArg: -1,
			CWE:       "CWE-1004",
			Finding:   "Session cookie readable by script",
			Reason:    "a cookie that carries a credential must not be readable by script, or any cross-site scripting anywhere on the origin becomes account takeover",
			Rationale: "set_cookie() passes no httponly keyword",
		},
		{
			// Written down explicitly, which is a decision rather than an omission.
			ID: "cookie-http-only-disabled", Method: "cookie", ArgIndex: -1, Qualifiers: credentialCookie,
			Disallowed: []string{"httponly=false"},
			CWE:        "CWE-1004",
			Finding:    "Session cookie readable by script",
			Reason:     "a cookie that carries a credential must not be readable by script, or any cross-site scripting anywhere on the origin becomes account takeover",
			Rationale:  "httpOnly is set to false",
		},
		{
			ID: "cookie-http-only-disabled", Method: "set_cookie", ArgIndex: -1, Qualifiers: credentialCookie,
			Disallowed: []string{"httponly=false"},
			CWE:        "CWE-1004",
			Finding:    "Session cookie readable by script",
			Reason:     "a cookie that carries a credential must not be readable by script, or any cross-site scripting anywhere on the origin becomes account takeover",
			Rationale:  "httponly is set to False",
		},
		{
			// Absence is NOT claimed for Secure. Real code writes
			// `secure: process.env.NODE_ENV === "production"`, which is correct and is not
			// a literal, and a rule that demanded the attribute be written down would
			// report every application that does the right thing conditionally. An
			// explicit false is a different matter: it is a decision, and it is here.
			ID: "cookie-not-secure", Method: "cookie", ArgIndex: -1, Qualifiers: credentialCookie,
			Disallowed: []string{"secure=false"},
			CWE:        "CWE-614",
			Finding:    "Credential cookie sent over plaintext",
			Reason:     "without the Secure attribute the cookie is sent on plain HTTP, where anyone on the path can read it",
			Rationale:  "secure is set to false",
		},
		{
			ID: "cookie-not-secure", Method: "set_cookie", ArgIndex: -1, Qualifiers: credentialCookie,
			Disallowed: []string{"secure=false"},
			CWE:        "CWE-614",
			Finding:    "Credential cookie sent over plaintext",
			Reason:     "without the Secure attribute the cookie is sent on plain HTTP, where anyone on the path can read it",
			Rationale:  "secure is set to False",
		},
		{
			// SameSite=None is legitimate -- an embedded widget or an OAuth flow needs
			// it -- so this reports and never gates, the same treatment a weak hash gets
			// and for the same reason: the call does not carry the fact that decides it.
			ID: "cookie-same-site-none", Method: "cookie", ArgIndex: -1, Qualifiers: credentialCookie,
			Disallowed:   []string{"samesite=none"},
			DependsOnUse: "an embedded widget and an OAuth flow both legitimately need a cross-site cookie, and the call does not carry which case this is",
			CWE:          "CWE-1275",
			Finding:      "Credential cookie sent on cross-site requests",
			Reason:       "SameSite=None lets the cookie ride requests a third-party site makes, which is what cross-site request forgery needs",
			Rationale:    "sameSite is set to none",
		},
		{
			ID: "cookie-same-site-none", Method: "set_cookie", ArgIndex: -1, Qualifiers: credentialCookie,
			Disallowed:   []string{"samesite=none"},
			DependsOnUse: "an embedded widget and an OAuth flow both legitimately need a cross-site cookie, and the call does not carry which case this is",
			CWE:          "CWE-1275",
			Finding:      "Credential cookie sent on cross-site requests",
			Reason:       "SameSite=None lets the cookie ride requests a third-party site makes, which is what cross-site request forgery needs",
			Rationale:    "samesite is set to None",
		},

		// The weak-hash rules that stood here matched the ALGORITHM NAME and said in their
		// own text that they could not tell what the digest was for. They are now a
		// classification (`weak-digest`) judged where the digest lands: at a comparison, at
		// a verification call, or in the field a password is checked against. The
		// measurement that moved them is in the loop issue -- 42 findings across ten
		// repositories, 39 of them worthless -- and the reason they could not stay here is
		// that a call shape sees one line and the question is about a second one.
		// A SESSION store's own cookie, configured where the store is made rather than
		// where a cookie is set. The attributes are the same three and mean the same
		// things; what changes is that they are written one level down inside a `cookie`
		// group, which only became readable when the frontends started reading nested
		// options.
		//
		// Named by CALLEE, and that is a correction rather than a preference. The first
		// version identified a session store by the presence of a `secret` option, on the
		// reasoning that a call which signs cookies with a secret is a session store
		// whatever it is called. Measured on the clean corpus that produced 126 findings:
		// a `secret` key appears in webhook configuration, OAuth clients, provider
		// factories and test fixtures, and none of them sets a cookie. A short list of
		// packages misses the next wrapper somebody writes, and that is the cheaper
		// mistake.
		{
			ID: "cookie-http-only-disabled", Symbol: "express-session.default", Keyword: "httpOnly",
			Disallowed: []string{"false"},
			CWE:        "CWE-1004",
			Finding:    "Session cookie readable by script",
			Reason:     "a session cookie without HttpOnly can be read by any script that runs on the page, which is what turns a scripting bug into a stolen session",
			Rationale:  "the session store's cookie is configured with httpOnly false",
		},
		{
			ID: "cookie-not-secure", Symbol: "express-session.default", Keyword: "secure",
			Disallowed: []string{"false"},
			CWE:        "CWE-614",
			Finding:    "Session cookie sent over plain HTTP",
			Reason:     "without Secure the browser sends this cookie over an unencrypted connection, where anyone on the path reads it",
			Rationale:  "the session store's cookie is configured with secure false",
		},
		{
			ID: "long-lived-session", Symbol: "express-session.default", Keyword: "maxAge", AboveValue: atMost(2592000000),
			CWE:       "CWE-613",
			Finding:   "Session cookie valid for longer than a month",
			Reason:    "a credential that stays valid for a year is a credential an attacker who steals it keeps for a year, and nothing the user does afterwards takes it back",
			Rationale: "the session store's cookie lifetime is written in the call, in milliseconds",
		},
		{
			// The key the cookie is SIGNED with. Written into the source it is in every
			// clone of the repository, so anybody holding the repository can mint a
			// session for anybody -- and the example values are in every tutorial too.
			ID: "hardcoded-secret", Symbol: "express-session.default", Keyword: "secret", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "secret", NoneOf: []string{"null", "none", "undefined", "false", "true"}}},
			CWE:        "CWE-798",
			Finding:    "Secret written into the source",
			Reason:     "a key in the source is in every clone of the repository and stays in its history after it is changed, and a session signing key in the source means anybody holding the repository can mint a session",
			Rationale:  "the session store's secret is given a value written in the call",
		},
		{
			ID: "cookie-http-only-disabled", Symbol: "cookie-session.default", Keyword: "httpOnly",
			Disallowed: []string{"false"},
			CWE:        "CWE-1004",
			Finding:    "Session cookie readable by script",
			Reason:     "a session cookie without HttpOnly can be read by any script that runs on the page, which is what turns a scripting bug into a stolen session",
			Rationale:  "the session store's cookie is configured with httpOnly false",
		},
		{
			ID: "cookie-not-secure", Symbol: "cookie-session.default", Keyword: "secure",
			Disallowed: []string{"false"},
			CWE:        "CWE-614",
			Finding:    "Session cookie sent over plain HTTP",
			Reason:     "without Secure the browser sends this cookie over an unencrypted connection, where anyone on the path reads it",
			Rationale:  "the session store's cookie is configured with secure false",
		},
		{
			ID: "long-lived-session", Symbol: "cookie-session.default", Keyword: "maxAge", AboveValue: atMost(2592000000),
			CWE:       "CWE-613",
			Finding:   "Session cookie valid for longer than a month",
			Reason:    "a credential that stays valid for a year is a credential an attacker who steals it keeps for a year, and nothing the user does afterwards takes it back",
			Rationale: "the session store's cookie lifetime is written in the call, in milliseconds",
		},
		{
			// The key the cookie is SIGNED with. Written into the source it is in every
			// clone of the repository, so anybody holding the repository can mint a
			// session for anybody -- and the example values are in every tutorial too.
			ID: "hardcoded-secret", Symbol: "cookie-session.default", Keyword: "secret", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "secret", NoneOf: []string{"null", "none", "undefined", "false", "true"}}},
			CWE:        "CWE-798",
			Finding:    "Secret written into the source",
			Reason:     "a key in the source is in every clone of the repository and stays in its history after it is changed, and a session signing key in the source means anybody holding the repository can mint a session",
			Rationale:  "the session store's secret is given a value written in the call",
		},
		{
			ID: "cookie-http-only-disabled", Symbol: "koa-session.default", Keyword: "httpOnly",
			Disallowed: []string{"false"},
			CWE:        "CWE-1004",
			Finding:    "Session cookie readable by script",
			Reason:     "a session cookie without HttpOnly can be read by any script that runs on the page, which is what turns a scripting bug into a stolen session",
			Rationale:  "the session store's cookie is configured with httpOnly false",
		},
		{
			ID: "cookie-not-secure", Symbol: "koa-session.default", Keyword: "secure",
			Disallowed: []string{"false"},
			CWE:        "CWE-614",
			Finding:    "Session cookie sent over plain HTTP",
			Reason:     "without Secure the browser sends this cookie over an unencrypted connection, where anyone on the path reads it",
			Rationale:  "the session store's cookie is configured with secure false",
		},
		{
			ID: "long-lived-session", Symbol: "koa-session.default", Keyword: "maxAge", AboveValue: atMost(2592000000),
			CWE:       "CWE-613",
			Finding:   "Session cookie valid for longer than a month",
			Reason:    "a credential that stays valid for a year is a credential an attacker who steals it keeps for a year, and nothing the user does afterwards takes it back",
			Rationale: "the session store's cookie lifetime is written in the call, in milliseconds",
		},
		{
			// The key the cookie is SIGNED with. Written into the source it is in every
			// clone of the repository, so anybody holding the repository can mint a
			// session for anybody -- and the example values are in every tutorial too.
			ID: "hardcoded-secret", Symbol: "koa-session.default", Keyword: "secret", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "secret", NoneOf: []string{"null", "none", "undefined", "false", "true"}}},
			CWE:        "CWE-798",
			Finding:    "Secret written into the source",
			Reason:     "a key in the source is in every clone of the repository and stays in its history after it is changed, and a session signing key in the source means anybody holding the repository can mint a session",
			Rationale:  "the session store's secret is given a value written in the call",
		},
		{
			ID: "cookie-http-only-disabled", Symbol: "client-sessions.default", Keyword: "httpOnly",
			Disallowed: []string{"false"},
			CWE:        "CWE-1004",
			Finding:    "Session cookie readable by script",
			Reason:     "a session cookie without HttpOnly can be read by any script that runs on the page, which is what turns a scripting bug into a stolen session",
			Rationale:  "the session store's cookie is configured with httpOnly false",
		},
		{
			ID: "cookie-not-secure", Symbol: "client-sessions.default", Keyword: "secure",
			Disallowed: []string{"false"},
			CWE:        "CWE-614",
			Finding:    "Session cookie sent over plain HTTP",
			Reason:     "without Secure the browser sends this cookie over an unencrypted connection, where anyone on the path reads it",
			Rationale:  "the session store's cookie is configured with secure false",
		},
		{
			ID: "long-lived-session", Symbol: "client-sessions.default", Keyword: "maxAge", AboveValue: atMost(2592000000),
			CWE:       "CWE-613",
			Finding:   "Session cookie valid for longer than a month",
			Reason:    "a credential that stays valid for a year is a credential an attacker who steals it keeps for a year, and nothing the user does afterwards takes it back",
			Rationale: "the session store's cookie lifetime is written in the call, in milliseconds",
		},
		{
			// The key the cookie is SIGNED with. Written into the source it is in every
			// clone of the repository, so anybody holding the repository can mint a
			// session for anybody -- and the example values are in every tutorial too.
			ID: "hardcoded-secret", Symbol: "client-sessions.default", Keyword: "secret", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "secret", NoneOf: []string{"null", "none", "undefined", "false", "true"}}},
			CWE:        "CWE-798",
			Finding:    "Secret written into the source",
			Reason:     "a key in the source is in every clone of the repository and stays in its history after it is changed, and a session signing key in the source means anybody holding the repository can mint a session",
			Rationale:  "the session store's secret is given a value written in the call",
		},
		{
			// A signing key written into the source. The rule tests only whether it was
			// WRITTEN, which is also what makes it precise: a key read from the
			// environment or a vault is not a literal and never matches. Nothing here
			// inspects the string, guesses at entropy, or keeps a list of what a secret
			// looks like.
			ID: "hardcoded-secret", Symbol: "jsonwebtoken.sign", ArgIndex: 1, AnyLiteral: true,
			CWE:       "CWE-798",
			Finding:   "Secret written into the source",
			Reason:    "a key in the source is in every clone of the repository and stays in its history after it is changed",
			Rationale: "the second argument to sign() is the signing key",
		},
		{
			ID: "hardcoded-secret", Symbol: "jsonwebtoken.verify", ArgIndex: 1, AnyLiteral: true,
			CWE:       "CWE-798",
			Finding:   "Secret written into the source",
			Reason:    "a key in the source is in every clone of the repository and stays in its history after it is changed",
			Rationale: "the second argument to verify() is the signing key",
		},
		{
			ID: "hardcoded-secret", Symbol: "crypto.createHmac", ArgIndex: 1, AnyLiteral: true,
			CWE:       "CWE-798",
			Finding:   "Secret written into the source",
			Reason:    "a key in the source is in every clone of the repository and stays in its history after it is changed",
			Rationale: "the second argument to createHmac() is the key",
		},
		{
			// Unlike a broken hash, this does not depend on use. A hash has honest
			// non-security jobs -- cache keys, content addressing, Gravatar -- and MD5 is
			// only wrong when collision resistance is what makes the thing work.
			// Encryption has no such second life: DES is not an acceptable way to encrypt
			// something for a purpose that does not need encryption, because nothing
			// needs encryption for a purpose that does not need it. So this one gates.
			ID: "weak-cipher", Symbol: "crypto.createCipheriv", ArgIndex: 0,
			Disallowed: []string{"des", "des-ecb", "des-cbc", "rc4", "rc2", "bf", "blowfish",
				"aes-128-ecb", "aes-192-ecb", "aes-256-ecb"},
			CWE:       "CWE-327",
			Finding:   "Broken or risky cipher",
			Reason:    "the cipher is broken, or the mode leaks structure of the plaintext",
			Rationale: "createCipheriv() is given the algorithm and mode by name",
		},
		{
			ID: "weak-cipher", Symbol: "crypto.createDecipheriv", ArgIndex: 0,
			Disallowed: []string{"des", "des-ecb", "des-cbc", "rc4", "rc2", "bf", "blowfish",
				"aes-128-ecb", "aes-192-ecb", "aes-256-ecb"},
			CWE:       "CWE-327",
			Finding:   "Broken or risky cipher",
			Reason:    "the cipher is broken, or the mode leaks structure of the plaintext",
			Rationale: "createDecipheriv() is given the algorithm and mode by name",
		},
		{
			// Node spells the same decision as an option rather than an argument, and it
			// is matched wherever it appears: an https.Agent, tls.connect, an axios
			// instance, a library's own config. The option name is the evidence.
			ID: "disabled-certificate-check", AnyCall: true, ArgIndex: -1,
			Disallowed: []string{"rejectunauthorized=false"},
			CWE:        "CWE-295",
			Finding:    "Certificate verification disabled",
			Reason:     "a connection that does not verify its peer authenticates nobody, so transport encryption protects against nothing",
			Rationale:  "rejectUnauthorized is set to false, which accepts any certificate",
		},
		{
			// Flask's debug server exposes the Werkzeug console, which executes Python
			// sent to it. Reaching production with this on is remote code execution, and
			// it is one keyword.
			ID: "debug-mode-enabled", Method: "run", ArgIndex: -1,
			Disallowed:           []string{"debug=true"},
			CWE:                  "CWE-489",
			Finding:              "Debug mode enabled",
			Reason:               "the debug server exposes an interactive console that executes code sent to it, so this is remote code execution wherever it is reachable",
			Rationale:            "run() is passed debug=True",
			ConfigurationEnabled: true,
		},
		{
			// aiohttp's `Application(debug=True)`, which is the same decision at a second
			// framework: the debug middleware answers a failed request with the traceback
			// and the local variables of every frame.
			ID: "debug-mode-enabled", Symbol: "aiohttp.web.Application", ArgIndex: -1,
			Disallowed:           []string{"debug=true"},
			CWE:                  "CWE-489",
			Finding:              "Debug mode enabled",
			Reason:               "debug mode answers a failed request with the traceback and the local variables of every frame, which describes the system to whoever provoked the failure",
			Rationale:            "Application() is constructed with debug=True",
			ConfigurationEnabled: true,
		},
		{
			ID: "debug-mode-enabled", Symbol: "web.Application", ArgIndex: -1,
			Disallowed:           []string{"debug=true"},
			CWE:                  "CWE-489",
			Finding:              "Debug mode enabled",
			Reason:               "debug mode answers a failed request with the traceback and the local variables of every frame, which describes the system to whoever provoked the failure",
			Rationale:            "Application() is constructed with debug=True",
			ConfigurationEnabled: true,
		},
		{
			// The dangerous part is the COMBINATION. Credentialed cross-origin requests
			// are ordinary; what makes them exploitable is an origin the server reflects
			// or wildcards, which lets any site on the internet make them as the victim.
			ID: "permissive-cors", AnyCall: true, ArgIndex: -1,
			Disallowed: []string{"credentials=true"},
			Qualifiers: []ArgCondition{{Keyword: "origin", AnyOf: []string{"*", "true"}}},
			// Measured, and it cost the clean corpus its only gating finding. hoppscotch
			// writes exactly this call inside the else branch of `if (isProduction)`,
			// with a whitelist on the other side. The call says what this rule claims;
			// what makes it acceptable is a condition the call does not carry, and no
			// reading of the call site could have known. Reported, because relaxed
			// development settings do reach production -- but never a reason to stop a
			// build, and a gate that fired on this idiom would be switched off.
			DependsOnUse: "whether this runs in production depends on the branch it sits in, which the call does not carry -- the common idiom guards a relaxed policy behind an environment check",
			CWE:          "CWE-942",
			Finding:      "Credentialed requests accepted from any origin",
			Reason:       "reflecting or wildcarding the origin while allowing credentials lets any site make authenticated requests as whoever is signed in",
			Rationale:    "credentials are allowed and the origin is not restricted",
		},
		{
			ID: "disabled-certificate-check", Symbol: "requests.get", ArgIndex: -1,
			Disallowed: []string{"verify=false"},
			CWE:        "CWE-295",
			Finding:    "Certificate verification disabled",
			Reason:     "a connection that does not verify its peer authenticates nobody, so transport encryption protects against nothing",
			Rationale:  "verify=False turns off certificate validation for this request",
		},
		{
			ID: "disabled-certificate-check", Symbol: "requests.post", ArgIndex: -1,
			Disallowed: []string{"verify=false"},
			CWE:        "CWE-295",
			Finding:    "Certificate verification disabled",
			Reason:     "a connection that does not verify its peer authenticates nobody, so transport encryption protects against nothing",
			Rationale:  "verify=False turns off certificate validation for this request",
		},
	}
}

// DecisionRule is a weakness visible in a COMPARISON rather than in a call.
//
// The engine's fourth analysis kind, and the smallest. A flow analysis asks where data
// goes; this asks what a branch was decided ON. `if (req.body.role === "admin")` sends
// nothing anywhere -- the defect is entirely that the server believed a claim the sender
// made about themselves.
//
// It is deliberately not a channel. A comparison has no arguments and no callee, and
// dressing it up as a call would mean inventing both.
type DecisionRule struct {
	ID string
	// Class is the classification one side of the comparison must carry. EMPTY means the
	// rule is about the comparison ITSELF rather than about what is being compared:
	// `x is "admin"` in Python asks whether two strings are the same OBJECT, which for
	// two equal strings is not guaranteed and is a different question from the one the
	// author meant to ask. No classification is involved and none should be required.
	Class string
	// OtherClasses requires the opposite operand to carry at least one of these
	// classifications. A caller value compared with another runtime value is ordinary;
	// the timing weakness begins only when that other value is a secret or digest.
	OtherClasses []string
	// Ops narrows to particular operators, or empty for any. Equality and inequality are
	// how a privilege is tested; ordering comparisons on a role are rare enough that
	// including them would be reaching.
	Ops []string

	// OtherBelow requires the OTHER side of the comparison to be a number written in the
	// source and smaller than this.
	//
	// A password's length is the case. `len(password) < 6` and `len(password) > 72` are
	// the same shape and opposite judgements -- one is a policy that permits a weak
	// password, the other is a library's maximum -- and the number is the only thing that
	// tells them apart. A threshold computed at runtime is not a number written in the
	// source and is not matched.
	OtherBelow *int

	// OtherAtLeast requires that same number to be at least this, which is how a
	// THRESHOLD is told from a PRESENCE test.
	//
	// `password.length > 0` and `secret.length !== 0` ask whether anything was sent at
	// all, and every application asks it. A policy that admits a short password is a
	// comparison against a small number that is not zero or one, and directus's
	// `client_secret.length > 0` is the reason this is written down.
	OtherAtLeast *int

	// OtherIsText requires the other side to be a string written into the source.
	OtherIsText bool

	// SideFrom requires the compared side to be the RESULT of one of these calls, for a
	// rule that has no classification to find a side by.
	//
	// `Array.isArray(x) === "true"` and `crypto.verify(...) === 0` are both comparisons
	// whose answer is known before the program runs: the call returns a boolean and the
	// other side is not one, so the test can never succeed. The symbol is what fixes the
	// type -- no inference is involved and none is available.
	SideFrom []string

	// OtherNamed requires the other side to BE one of these names.
	//
	// `x === NaN` is the case, and it is a comparison whose answer is known without
	// running it: every comparison with NaN is false, including the inequality, so a
	// branch that tests for one is a branch that never runs. A check that never runs is
	// not a check. The value has no literal to match on -- it is a name the language
	// provides -- so neither OtherIsText nor a literal test can reach it.
	OtherNamed []string
	// OtherNameContains narrows a relation whose opposite operand is a named container.
	// Membership in a blacklist establishes something; membership in a cache does not,
	// and the container is the only place those character-for-character spellings differ.
	OtherNameContains []string

	// RequiresUnprojected forbids the judgement for a value read OUT of a structure the
	// classification reached.
	//
	// A credential handed to a function and a field read back off what it returned are
	// not the same value: `session.tenantId !== current` compares a tenant id, and that a
	// token was involved in producing the session does not make a tenant id a secret.
	// Four findings in one production repository were exactly that.
	RequiresUnprojected bool

	// RequiresUnenclosed forbids the judgement for a STRUCTURE the classified value was
	// put into, which is the same question read the other way round.
	//
	// medplum builds `{ ...login, scope }` out of the scope the caller asked for and
	// hands the object to the repository. Eight frames down, in a module that rewrites
	// attachment URLs, a generic helper opens with `if (input === null || input ===
	// undefined) return input`, and `input` is that object. Nothing there reads a claim
	// or decides anything about the caller; the object merely still contains a field the
	// caller filled in. The rule reported it as a branch trusting the caller's own claim,
	// at a line where the expression it named does not occur.
	RequiresUnenclosed bool

	// RequiresWholeValue forbids the judgement for a value the classification was built
	// INTO rather than one it is.
	//
	// The mirror image of RequiresUnprojected, and the digest rules need both.
	// `f"{md5(url).hexdigest()}{extension}"` is a filename that CONTAINS a digest, and
	// linkding compares one against the filename already on the record to decide whether
	// to write the row again -- a question about whether the preview changed, not about
	// whether two inputs are the same one. The channel that judges an unsalted hash has
	// asked this of a flow path since it was written; a comparison is entitled to the
	// same reading.
	RequiresWholeValue bool

	// OtherWrittenDigest requires that where the other side is WRITTEN INTO THE SOURCE,
	// it is written as a digest -- a run of hex long enough to be one.
	//
	// A digest compared against a recorded digest is the clearest case the rule has, and
	// the recorded one is a hex constant. A digest compared against a NUMBER is not a
	// comparison of digests at all, whatever the classification says arrived there:
	// medplum hands a script's SHA-1 to Redis EVALSHA and tests the numeric reply for 1,
	// and the class rode through an unresolved call into a value that is not a digest and
	// never was. Narrower than refusing every literal, which would throw away the
	// recorded-checksum case that is the rule's plainest true finding. A digest written
	// in base64 is not matched and is a stated miss.
	OtherWrittenDigest bool

	// OtherNameExcept refuses the judgement when the other operand's name says it is
	// something a different rule has a better answer for. The name is read through an
	// anonymous subscript, because `pwhash[5:]` and `pwhash` are the same value and only
	// one of them has a name.
	OtherNameExcept []string

	// SideVia narrows to a classified side that is a particular DERIVATION of the
	// classified value, named by the property leaf or the function that produced it.
	//
	// A password policy is about the password's LENGTH. `password.length < 6` and
	// `len(password) < 6` are the check; `password[0] < 'a'` and `parts.length < 6` on
	// something a password was involved in producing are not, and once a request value
	// reaches a library it is involved in producing a great many things. Measured on the
	// clean corpus without this, one directus route sent a password into the permissions
	// engine and produced 51 findings, every one of them a length check on something
	// else.
	SideVia []string

	// OtherNotSameClass forbids the judgement when BOTH sides carry the classification.
	//
	// `req.body.password == req.body.cpassword` is a password confirmation: two values the
	// same caller just sent, compared against each other. There is no secret to learn from
	// how long it takes, because the person timing it wrote both. The timing rule found
	// exactly this in the vulnerable corpus and was right about the shape and wrong about
	// the weakness.
	OtherNotSameClass bool
	// OtherClassOverridesSame permits a derived proof to be compared with the input it
	// was computed from. An HMAC over a request body still becomes a server-held expected
	// digest; a second request field does not. The independent derived class is the fact
	// that separates them.
	OtherClassOverridesSame []string

	// OtherNotAbsent forbids the judgement when the other side is the language's way of
	// writing NOTHING -- an empty string, None, null, undefined.
	//
	// `s == ""` asks whether anything arrived at all, and every function that takes a
	// string asks it. It is not a comparison that establishes anything, so it is not a
	// comparison a rule about what a value PROVES has any business reading. Narrower
	// than OtherNotLiteral on purpose: a digest compared against a digest written into
	// the source is a recorded checksum and is exactly the case worth reporting, so
	// excluding every literal would throw that away to be rid of this.
	OtherNotAbsent bool

	// OtherNotObjectBrand excludes JavaScript's standardized type-tag comparison, and
	// only that comparison. `Object.prototype.toString.call(value) === "[object Error]"`
	// asks what kind of object arrived; the bracketed text is a public brand, not a
	// password. The producer is part of the requirement so a caller credential genuinely
	// compared with the same text remains a hardcoded credential.
	OtherNotObjectBrand bool

	// SkippedByOperandPresence requires the comparison to be conjoined with a test that
	// each of its OWN operands is present, so that whatever it decides does not happen
	// when one of them is missing.
	//
	//	if (decodedToken.scope && scope && decodedToken.scope !== scope) throw ...
	//
	// `a && b && a !== b` is a general and dangerous idiom: the check is written as a
	// conjunction, and the two operands it compares are the same two the conjunction
	// requires to be there, so a caller who omits either one satisfies the condition
	// trivially and the comparison settles nothing. It is also an ordinary and correct
	// idiom -- a program that renames a file only when both names exist and differ has
	// written exactly this -- which is why the two fields below are part of the same
	// rule rather than optional refinements of it. Measured over ten production
	// repositories this shape alone occurs SEVEN times.
	SkippedByOperandPresence bool

	// RefusesWhenTrue requires the branch to leave by THROWING on the side where the
	// comparison held.
	//
	// The polarity is what turns a skippable condition into a skippable control. A
	// condition that refuses when it holds loses a refusal when an operand goes missing;
	// a condition that does WORK when it holds loses the work, which is what the presence
	// test was written to arrange. Of the seven occurrences above, two refuse: documenso's
	// presign-token verifier and an archivebox admin action that renames a directory.
	RefusesWhenTrue bool

	// SidesNameOneThing requires the two operands to have been written with the same
	// trailing name -- `decodedToken.scope` against `scope`.
	//
	// This is what separates a VERIFICATION from a difference test, and it is the
	// program's own statement of which two things it believes should agree. The five
	// occurrences it removes compare things that are not each other and are not meant to
	// be: `old_path` against `new_path`, `line.fontRef` against `modalFontRef`,
	// `address` against `old_address`, a request port against a configured one. Of the
	// seven, ONE compares a name with itself, and it is documenso's.
	//
	// Deliberately an exact match on the leaf rather than a containment test. `scope`
	// against `expectedScope` is the same claim and is a stated miss, because the
	// containment that would admit it also admits `fontRef` inside `modalFontRef` and
	// `address` inside `old_address` -- two of the five this exists to remove.
	SidesNameOneThing bool

	// OtherNotLiteral requires the other side to be a runtime value rather than
	// something written down.
	//
	// A secret compared against a secret is two runtime values. A secret compared against
	// a literal is a presence check (`=== undefined`), a flag test, or a hardcoded
	// credential -- which is a different weakness with its own number. Requiring the
	// other side to be unwritten is what separates them.
	OtherNotLiteral bool

	CWE       string
	Finding   string
	Reason    string
	Rationale string
}

func builtinDecisions() []DecisionRule {
	equality := []string{"==", "===", "!=", "!==", "is", "is not"}
	return []DecisionRule{
		{
			ID: "caller-decides-own-authority", Class: "caller-asserted-authority", Ops: equality,
			RequiresUnprojected: true,
			RequiresUnenclosed:  true,
			CWE:                 "CWE-807",
			Finding:             "Security decision made on the caller's own claim",
			Reason:              "a field the caller sent is a statement the caller made about themselves, and a branch that trusts it lets them choose which branch runs",
			Rationale:           "the comparison decides on a value that arrived in the request",
		},
		{
			// A password policy that permits a short password. What makes this decidable
			// at all is that the length is being compared to a number the source
			// contains: eight characters is where every published guidance starts, and a
			// check that admits fewer is a check that admits a password worth guessing.
			//
			// Only ordering comparisons, and only against a small number. `len(password)
			// > 72` is bcrypt's maximum and the same shape read the other way.
			ID: "weak-password-policy", Class: "caller-credential",
			Ops:          []string{"<", "<=", ">", ">=", "Lt", "LtE", "Gt", "GtE"},
			SideVia:      []string{"length", "len", "size"},
			OtherBelow:   atLeast(8),
			OtherAtLeast: atLeast(2),
			CWE:          "CWE-521",
			Finding:      "Password policy admits a password shorter than eight characters",
			Reason:       "a password this short can be guessed offline in minutes once the hashes leak, and the length the policy admits is the length people will use",
			Rationale:    "the caller's password is measured against a number written in the source",
		},
		{
			// `password is "admin"` asks whether two strings are the same OBJECT. Python
			// interns some strings and not others, so the answer depends on how the value
			// was built rather than on what it says -- and the check silently stops
			// working the day the string arrives from somewhere else.
			//
			// No classification: the defect is in the comparison itself, whatever is
			// being compared.
			// A boolean read as a STATUS CODE. `crypto.verify(...) === 0` is how a C
			// programmer checks a return value, and in these languages the call answers
			// true or false -- so the check inverts, and a signature that failed to
			// verify reads as one that passed.
			ID:         "boolean-compared-to-number",
			Ops:        []string{"===", "!==", "==", "!="},
			SideFrom:   []string{"crypto.verify", "crypto.timingSafeEqual", "hmac.compare_digest", "secrets.compare_digest", "bcrypt.compareSync"},
			OtherBelow: atMost(2),
			CWE:        "CWE-253",
			Finding:    "Verification result compared as a status code",
			Reason:     "the call answers true or false rather than returning a code, so comparing it with a number tests something the call never says -- and a signature that failed can read as one that passed",
			Rationale:  "one side is a call that returns a boolean and the other is a small number written in the source",
		},
		{
			// Every comparison with NaN is false, the inequality included, so a branch
			// that tests for one is a branch that never runs -- and in a check, a branch
			// that never runs is not a check. Nothing has to reach this and no
			// classification is involved: the comparison is wrong as written.
			ID:         "compared-to-nan",
			Ops:        []string{"==", "===", "!=", "!=="},
			OtherNamed: []string{"NaN", "Number.NaN", "math.nan", "numpy.nan", "np.nan"},
			CWE:        "CWE-1077",
			Finding:    "Comparison with a value that equals nothing",
			Reason:     "every comparison with NaN is false, so this branch never runs however the value arrives -- and a test that cannot succeed is not a test",
			Rationale:  "the other side of the comparison is the not-a-number value itself",
		},
		{
			// A verification whose condition includes the PRESENCE of the value being
			// verified. `if (claim && expected && claim !== expected) throw` refuses when
			// the two disagree and does nothing at all when either is missing -- so the
			// party who supplies one of them decides whether the check happens, by
			// leaving it out.
			//
			// documenso's embedded-signing presign token is the measured case. The
			// verifier takes `scope` as an OPTIONAL parameter and writes
			// `decodedToken.scope && scope && decodedToken.scope !== scope`; two file
			// routes call it with no scope at all, so a token minted for one purpose is
			// accepted for every purpose those routes serve. Nothing is missing from the
			// program -- the check is right there, and reads as a scope check to anyone
			// scanning the file.
			//
			// No classification, deliberately. The defect is in the comparison's own
			// shape rather than in what reaches it: this condition settles nothing about
			// whatever arrives on either side of it, and requiring a taint path would
			// make the judgement depend on whether the analysis could follow a JWT
			// through a decode call, which is a fact about the analysis and not about the
			// weakness.
			//
			// Three facts, and each one is a measurement. Across ten production
			// repositories the conjunction shape occurs seven times; requiring the
			// refusal leaves two; requiring the two sides to name one thing leaves one,
			// and it is documenso's. The five that naming removes are difference tests --
			// a rename that needs both paths, a font weight against the document's modal
			// font, a checkout address against the previous one -- and the one that the
			// refusal removes is an archivebox admin action that raises when a rename
			// would overwrite something. All six want their presence tests and would be
			// wrong without them.
			ID:                       "verification-skipped-by-absent-operand",
			Ops:                      []string{"!=", "!==", "<>", "NotEq", "IsNot"},
			SkippedByOperandPresence: true,
			RefusesWhenTrue:          true,
			SidesNameOneThing:        true,
			CWE:                      "CWE-863",
			Finding:                  "A check that is skipped by omitting what it checks",
			Reason:                   "the refusal is conditioned on both values being present, so whoever supplies one of them can skip the check entirely by leaving it out, and the comparison settles nothing",
			Rationale:                "the comparison that decides the refusal is conjoined with tests that its own two operands are present",
		},
		{
			ID: "identity-compared-to-text", Ops: []string{"Is", "IsNot"}, OtherIsText: true,
			CWE:       "CWE-597",
			Finding:   "String compared by identity rather than by value",
			Reason:    "identity asks whether two strings are the same object, which for two equal strings is not guaranteed, so this check can pass or fail on how the value happened to be built",
			Rationale: "an identity comparison against a string written in the source",
		},
		{
			// A secret compared with the language's equality operator. Neither language
			// promises that comparison takes the same time whatever it is given, and
			// neither implementation delivers it: both return as soon as two characters
			// differ, so the time says how much of the guess was right and enough guesses
			// turn that into the whole value. The fix is a constant-time compare, which is
			// a CALL and leaves no comparison here to match.
			//
			// The other side must be a runtime value: comparing a token to a literal is a
			// presence check, a flag test, or a hardcoded credential, and the last of
			// those has its own number.
			ID: "non-constant-time-secret-comparison", Class: "caller-comparison-input",
			Ops:                     []string{"==", "===", "!=", "!==", "Eq", "NotEq"},
			OtherClasses:            []string{"computed-secret", "stored-secret", "weak-digest"},
			OtherNotLiteral:         true,
			OtherNotSameClass:       true,
			OtherClassOverridesSame: []string{"computed-secret", "weak-digest"},
			RequiresUnprojected:     true,
			CWE:                     "CWE-208",
			Finding:                 "Secret compared in variable time",
			Reason:                  "the comparison stops at the first byte that differs, so how long it takes says how much of the guess was right, and enough guesses recover the whole value",
			Rationale:               "a value the caller sent as a credential is compared with the language's equality operator",
		},
		{
			// The other half of the rule above, and the reason that one requires a
			// runtime value on the far side: "comparing a token to a literal is a
			// presence check, a flag test, or a hardcoded credential, and the last of
			// those has its own number." This is that number.
			//
			// It is the `compares against` half of the credential judgement -- does THIS
			// program rely on the value being secret? -- and it is stated here rather
			// than inside the value-shape rules because only a comparison says whose
			// value is on the other side. A literal measured against something the
			// program computed for itself is an expected result or a format marker. A
			// literal measured against what a CALLER sent is the door, and the key to it
			// is in every clone of the repository.
			//
			// Nothing about the literal's shape is examined and nothing needs to be: a
			// four-character password admits a caller exactly as a forty-character one
			// does. The empty string is excluded because `token == ""` asks whether
			// anything arrived, and a value the same caller also sent is excluded
			// because that is a confirmation field.
			ID: "credential-admits-caller", Class: "caller-credential",
			Ops:                 []string{"==", "===", "!=", "!==", "Eq", "NotEq"},
			OtherIsText:         true,
			OtherNotAbsent:      true,
			OtherNotSameClass:   true,
			RequiresUnprojected: true,
			OtherNotObjectBrand: true,
			CWE:                 "CWE-798",
			Finding:             "Caller admitted by a credential written into the source",
			Reason:              "the value that decides whether this caller is let in is in every clone of the repository and stays in its history after it is changed, so nobody can revoke it without shipping a release",
			Rationale:           "a credential the caller sent is compared against a string written into the source",
		},
		{
			// A digest from a broken algorithm, tested against something. This is where a
			// weak hash stops being a fact about a call and becomes a weakness: the
			// comparison is the program stating that the digest STANDS IN for what it was
			// computed from, and collision resistance is precisely what makes that
			// substitution sound.
			//
			// Equality only, and that is a measured line rather than a cautious one.
			// Membership -- `digest in blacklist` -- is the same judgement written with a
			// different operator and would catch searxng's onion filter, which an
			// independent reader called the one true finding in its repository. It is
			// also, character for character, how a program asks whether a cache already
			// holds a key, and the corpus contains both. Equality is unambiguous;
			// membership is not, so the miss is stated here rather than paid for at every
			// cache in the corpus.
			//
			// The other side may be a literal: a digest compared against one written into
			// the source is a recorded checksum, which is the clearest case there is. It
			// has to be written as a DIGEST, though, and three of the four findings this
			// rule produced across ten production repositories are why the operator alone
			// was never enough to say what a comparison decides.
			//
			// medplum derives a Lua script's SHA-1 so it can address Redis's script cache
			// with it, hands it to EVALSHA, and tests the numeric reply for 1. The
			// classification rode through the unresolved call into a value that is not a
			// digest and never was, and OtherWrittenDigest is what says so: `=== 1` is not
			// a comparison of digests whatever arrived on the other side.
			//
			// linkding names a preview file after the MD5 of its URL, and compares the
			// name against the one already on the record to decide whether to write the
			// row again. The digest is a PART of that name -- `f"{hash}{extension}"` --
			// so the value compared is a filename that contains a digest rather than a
			// digest, which is the same distinction the unsalted-hash channel has drawn
			// since it was written and is what RequiresWholeValue asks here.
			//
			// mitmproxy's htpasswd verifier is the third and it is a real weakness named
			// wrongly, so it is handed to the rule below rather than silenced: a stored
			// password hash is not defeated by finding a collision, and saying that a
			// second input passes the check as readily as the right one is false there.
			ID: "weak-digest-compared", Class: "weak-digest",
			Ops:                 []string{"==", "===", "!=", "!==", "Eq", "NotEq"},
			RequiresUnprojected: true,
			RequiresWholeValue:  true,
			OtherNotAbsent:      true,
			OtherWrittenDigest:  true,
			OtherNameExcept:     []string{"password", "passwd", "pwhash", "pwd"},
			CWE:                 "CWE-328",
			Finding:             "Broken digest compared as proof",
			Reason:              "the comparison decides that two things are the same because their digests are, and this algorithm is broken against collision -- so a second input passes the check as readily as the right one",
			Rationale:           "a digest from a broken algorithm is what the comparison decides on",
		},
		{
			// The weakness the collision rule was reporting the wrong number for. A
			// submitted password is put through a plain digest and the result is compared
			// with the one on the account: the comparison is the program saying that this
			// digest IS the account's password verifier.
			//
			// Collision resistance is not what fails here and mitmproxy's reviewer was
			// right to say so -- finding two inputs with the same digest does not produce
			// a second password for a digest somebody else chose. What fails is the
			// construction: a single unsalted pass of a function built to be fast is
			// answered by a rainbow table for the passwords anybody has already tabulated
			// and by a GPU for the rest, and the salt has nowhere to go because the call
			// takes the password and nothing else.
			//
			// Named by the other operand, because the digest side says only that a hash
			// happened and the stored side is where the program says what the hash was
			// FOR -- the same reading, and the same four spellings, the store rule uses
			// for a password field. The exclusions are that rule's too: a reset URL, a
			// password POLICY and a confirmation field all carry the word and none of
			// them is a verifier.
			//
			// Scoped to the digests already classified as broken against collision, which
			// is narrower than the weakness: a password verified against an unsalted
			// SHA-256 is exactly as wrong and is not matched here, because the class that
			// would carry it also carries HMACs and random bytes, and an HMAC of a
			// password under a server-held key is a different construction with a
			// different answer.
			ID: "password-verified-by-plain-digest", Class: "weak-digest",
			Ops:                 []string{"==", "===", "!=", "!==", "Eq", "NotEq"},
			RequiresUnprojected: true,
			RequiresWholeValue:  true,
			OtherNotAbsent:      true,
			OtherNameContains:   []string{"password", "passwd", "pwhash", "pwd"},
			OtherNameExcept:     []string{"policy", "url", "link", "reset", "confirm", "repeat", "csrf", "xsrf", "hint", "expire", "changed", "last"},
			CWE:                 "CWE-916",
			Finding:             "Password verified against a plain unsalted digest",
			Reason:              "the stored value this password is checked against is a single pass of a fast digest with nowhere to put a salt, so whoever takes the store answers the common passwords from a table and the rest at the speed of the hardware",
			Rationale:           "a digest is compared against the value the program stores as a password",
		},
		{
			// Membership is a security decision only when the container says it is a
			// denial set. `digest in cache` is the identical operator over the identical
			// class and is how memoization is written, so the container name is a required
			// half of the judgement rather than an exclusion applied afterwards.
			ID: "membership-test-not-a-comparison", Class: "weak-digest",
			Ops:                 []string{"In", "NotIn"},
			OtherNameContains:   []string{"blacklist", "blocklist", "denylist"},
			RequiresUnprojected: true,
			RequiresWholeValue:  true,
			CWE:                 "CWE-328",
			Finding:             "Broken digest tested against a denial list",
			Reason:              "membership makes this digest the identity of the blocked value, and collisions let a second value make the same decision",
			Rationale:           "a digest from a broken algorithm decides membership in a container named as a denial list",
		},
		{
			// The Referer says where a request came from only in the sense that it says
			// whatever the sender wrote there. A browser sends it, a script omits it, and
			// anything at all can forge it.
			ID: "referer-decides-access", Class: "referer", Ops: equality,
			RequiresUnprojected: true,
			CWE:                 "CWE-293",
			Finding:             "Access decided on the Referer header",
			Reason:              "the Referer is written by whoever made the request, so a check against it is a check the caller can pass by choosing what to write",
			Rationale:           "the comparison decides on a header the caller controls",
		},
		{
			// A reverse lookup answers with whatever the owner of the ADDRESS block put
			// in the PTR record, and that is not the owner of the name it gives back.
			ID: "reverse-dns-decides-access", Class: "reverse-dns-name", Ops: equality,
			RequiresUnprojected: true,
			CWE:                 "CWE-350",
			Finding:             "Access decided on a reverse DNS name",
			Reason:              "a reverse lookup returns what the address's owner chose to publish, which is not evidence of who they are",
			Rationale:           "the comparison decides on the result of a reverse lookup",
		},
		{
			ID: "cookie-decides-authority", Class: "cookie-asserted-authority", Ops: equality,
			RequiresUnprojected: true,
			CWE:                 "CWE-565",
			Finding:             "Security decision made on a cookie",
			Reason:              "a cookie is a value the browser was handed and hands back, and getting it back is no evidence it came from here or came back unchanged",
			Rationale:           "the comparison decides on a cookie the caller returned",
		},
	}
}

// StoreRule is a weakness in what got WRITTEN somewhere, rather than in what was called or
// what was compared.
//
// A session is the case that needs it. `req.session.role = req.body.role` calls nothing and
// compares nothing: the caller's claim is simply moved to the far side of a trust boundary,
// and everything downstream that reads the session gets it back looking like something the
// server established.
type StoreRule struct {
	ID string
	// Class is the classification the written value must carry.
	Class string
	// Into names the destination, matched against the last segment of the base's access
	// path: `req.session` and `request.session` are both "session".
	Into []string
	// Path narrows further to particular keys written INTO that destination, or empty
	// for any. The environment holds a hundred harmless variables and one that decides
	// where the next program comes from.
	Path []string
	// PathContains matches a key by a WORD in it rather than by its whole name.
	//
	// Configuration keys are compound: `SECRET_KEY`, `SECRET_KEY_HMAC`, `JWT_SECRET`,
	// `MAIL_PASSWORD`. What they have in common is a word, and an exact list of the
	// spellings somebody thought of is wrong at the first application that adds a suffix.
	PathContains []string
	// PathExcept disqualifies, and is checked first. A double-submit CSRF token contains
	// the word `token` and is deliberately not a secret.
	PathExcept []string
	// PathExceptSuffix disqualifies when the final identifier word says the setting is
	// the NAME of the key rather than key material. `signingKeyId` identifies whichever
	// generated private key the runtime stored beside it; it cannot sign anything itself.
	// Suffix-only keeps `idSigningKey` available for a program that signs identifiers.
	PathExceptSuffix []string

	// FromLiteral requires the value WRITTEN to have been written into the source.
	//
	// The destination name narrows what the value is FOR; the literal still has to be a
	// value capable of filling that role. A key written into the source is in every clone
	// of the repository, while a value read from the environment is not written down and
	// never matches.
	FromLiteral bool

	// FromLiteralFallback also accepts a literal on the default side of `X || literal`.
	// The option is then a literal precisely when X is absent, which is the deployment
	// state a default describes. Kept separate from FromLiteral because following every
	// assignment to any literal would turn ordinary computed configuration into a secret.
	FromLiteralFallback bool

	// FromLiteralArgument accepts a literal written as an argument -- other than the
	// FIRST one -- of the call whose result was written.
	//
	// `X || literal` is one spelling of a default and the operator says so; every other
	// language and library spells it as a lookup with a fallback argument, and the
	// operator is not there to say anything. `os.environ.get("SECRET_KEY", "abc")`,
	// `os.getenv(...)`, environs' `env("SECRET_KEY", "abc")` and python-decouple's
	// `config("SECRET_KEY", default="abc")` are four libraries and one fact.
	//
	// The first argument is excluded and that exclusion is the entire rule. It is the
	// KEY -- the name of the variable being read -- and it is credential-shaped in every
	// one of these calls, so admitting it would report `SECRET_KEY = env("SECRET_KEY")`,
	// which is the CORRECT way to write the line. Everything after the key is a default
	// or an option, in every library that has this shape, which is why this needs to know
	// none of their names.
	FromLiteralArgument bool

	// NotPath excludes keys another rule already claims, so two rules can describe the
	// same destination at different granularities without reporting one line twice.
	NotPath []string
	// DirectPath requires the identity slot to be written directly on the destination.
	// A dotted key is an application namespace, not the session's principal slot:
	// wger's `trainer.identity` remembers who a trainer switched away from and
	// `gym.user` carries credentials for a follow-up display. Treating their final words
	// as `identity` and `user` produced both of CWE-384's measured findings and neither
	// was an identity change.
	DirectPath bool
	// RequiresUnprojected forbids the judgement for a value read OUT of something the
	// classification reached. `accountability.admin = userGlobalAccess.admin` writes a
	// field of what a server-side lookup returned, and that the lookup was once handed a
	// request does not make its answer the caller's.
	RequiresUnprojected bool

	// RequiresComposition and RequiresWholeValue ask opposite structural questions
	// about a property write. A URL with caller data after a fixed prefix lets the
	// caller alter path/query syntax; a URL supplied whole lets them choose its scheme.
	// Keeping these on the destination rule prevents either shape from being mistaken
	// for SSRF, whose channel asks whether the caller chose a server-side host.
	RequiresComposition bool
	RequiresWholeValue  bool
	// Context lets the store analysis apply the same sanitizer vocabulary as a call
	// channel. Assignment is the sink for DOM properties, but encodeURIComponent is no
	// less a URL-component encoder because no function is called at the destination.
	Context string

	// RequiresEntryFunction narrows a rule to writes that happen INSIDE a request
	// handler, rather than anywhere the data happens to reach.
	//
	// Taint answers "did this value come from a request", which is not the same question
	// as "did this line run while serving one". A plugin hook bus carries request data
	// into an initialisation function, and five findings in one production repository
	// were exactly that: a module-level allow-list, a login-strategy table and a
	// sanitiser configuration, all assembled at startup from a hook whose other callers
	// include a route.
	RequiresEntryFunction bool

	// IntoScope matches on how far the destination REACHES rather than on what it is
	// called. Process-wide state written from a request handler is read back by the next
	// request, and the name it happens to have says nothing about that.
	IntoScope string

	// KeyClass is the classification the KEY must carry, for a rule whose subject is
	// what the entry was filed under rather than what was filed.
	//
	// `cache[req.params.id] = row` writes a row the server produced under an identifier
	// the caller invented, and the two halves of that statement are different weaknesses.
	// What was written decides whether one request's data is answered to another; what it
	// was written UNDER decides how many entries there can ever be, because a container
	// gains one per distinct key and the caller has an unlimited supply.
	//
	// A literal key can never make the container grow past the number of literals in the
	// program, which is why only a computed key is matched at all.
	KeyClass string

	// IntoOutlivingRequest requires the destination to be reached through a binding no
	// request created: a name declared at a module's top level, or one the language
	// provides. A container that is made inside the handler dies with it however many
	// entries it gained, so the same statement in the same handler means nothing there.
	//
	// Read from the shape of the IR rather than from a name: the base of the write is
	// followed to the root of its property chain, and the root either belongs to a
	// module's top level or is a global. `IntoScope` answers the same question for an
	// assignment to a plain NAME, which is the only shape a frontend can decide by
	// itself; a subscript into a container is decided here because it is the same
	// question asked about a value the core can already see.
	IntoOutlivingRequest bool

	// AbsentSizeBound requires that nothing in the program measures the container's
	// extent against a number written in the source.
	//
	// A cache with a cap is a cache; a cache without one is a leak, and the difference
	// is a comparison. `if (cache.size > 1000) evict()` is the whole of what separates
	// them, so a rule that reports unbounded growth has to look for it -- and has to
	// look program-wide, because the eviction is routinely written in a different
	// function from the insertion.
	AbsentSizeBound bool

	// NotAfterLookup withdraws the judgement when a call handed the same key has already
	// DECIDED something before the write: the key was looked up, control branched on the
	// answer, and the write is on the far side of that branch.
	//
	// This is what separates a leak from a memo. `const row = await find(id); if (!row)
	// return 404; cache[id] = row` can only ever hold keys that name a row, and the
	// number of rows is not the caller's to choose. The identical write with the lookup
	// BELOW it, or with the lookup's answer not yet consulted, has no such ceiling.
	//
	// A basic block is the whole evidence and there is no guessing in it: a block
	// contains no branch, so a lookup in the same block as the write cannot have changed
	// whether the write runs. uptime-kuma asks `isMonitorPublic(id)` and installs a
	// permanent entry for `id` two lines later, in the same block, before reading the
	// answer.
	NotAfterLookup bool

	// KeyPure names the calls that decide nothing about a key beyond its own text, so
	// that a conversion is not mistaken for a lookup.
	//
	// `Number.isNaN(id)` and `/^[0-9]+$/.test(id)` are checks, and what they establish is
	// that the key is well FORMED -- and the set of well-formed keys is exactly as
	// unbounded as the set of keys. uptime-kuma's badge routes reject a non-numeric
	// monitor id two lines above installing an entry for whatever number arrived, which
	// is the shape this exists to keep visible.
	//
	// A method on a type the language itself declares is excluded without being named:
	// nothing a string can be asked about itself is a lookup, and the frontend already
	// says which receivers those are.
	KeyPure []string
	// AbsentCall names calls whose ABSENCE is the defect: the write is unremarkable and
	// what makes it a weakness is the thing that did not happen beside it.
	//
	// Installing an identity into a session is what every login does. Doing it without
	// rotating the session identifier is session fixation, because an identifier an
	// attacker planted before the login still names the session after it. The write is
	// the same write either way, so the rule cannot be about the write.
	//
	// Searched through the calls the function makes, the functions it passes as arguments
	// (a promise executor is how this is usually written), the local functions it calls,
	// and its own callers -- because the rotation and the assignment are routinely in
	// different functions, and a rule that demanded them in one would report every
	// application that factored its login out into a helper.
	//
	// A rule with an AbsentCall needs no classification: the write is the event, and
	// nothing has to have flowed anywhere for the missing call to be missing.
	AbsentCall []string
	// IdentityCalls are operations that replace the authenticated principal when they
	// receive a request as their receiver or first argument. The request role is part of
	// the match: `mailbox.login(user, password)` and a repository client's `login` method
	// use the same verb and change no HTTP identity.
	IdentityCalls []string
	// IntrinsicRotationSymbols are identity operations whose implementation guarantees
	// rotation. Their exact external identity is required; treating every `login` call
	// as Django would hide a custom login that writes the principal directly.
	IntrinsicRotationSymbols []string
	// IntrinsicRotationMethods are request methods whose framework contract includes
	// regeneration, such as Passport's req.logIn/req.login operation.
	IntrinsicRotationMethods []string
	// NotElement excludes a destination that is an ELEMENT of a collection.
	//
	// `sessions.forEach((session) => { session.user = ... })` writes to somebody else's
	// session, which is what an administrative dashboard listing logins does. It is named
	// `session` and it is not the caller's, and without this the rule reports a page for
	// displaying sessions as though it created one.
	NotElement bool
	// NotFrom names literal values that mean the field is being CLEARED rather than set.
	// `session.user_id = null` is a logout: the opposite of the weakness, written with the
	// same syntax.
	NotFrom []string

	// NotInto is the same exclusion on the DESTINATION rather than the key.
	//
	// `req.session.role = req.body.role` is a privilege set from the request AND a
	// caller's claim laundered across a trust boundary. Both readings are true and the
	// line is one line, so the narrower rule keeps it and the broader one stands aside.
	NotInto []string

	// OnInsert and OnUpdate name the option groups of a store call that says what to
	// write when the record is NEW and what to write when it ALREADY EXISTS.
	//
	// One call, two halves, and the program's own answer to a question an absence rule
	// would otherwise have to guess at. `prisma.recipient.upsert({ create: { email,
	// token: nanoid() }, update: { email } })` states that a recipient needs a fresh
	// token -- its own create says so -- and then rewrites the address without one. There
	// is no population to compare against and no other file to read: the two claims are
	// twelve lines apart in one expression.
	//
	// Every library that can insert-or-update spells this the same way, because it has
	// to: MongoDB separates `$setOnInsert` from `$set`, Sequelize takes `defaults`
	// alongside the values it matches on. The groups are named rather than inferred
	// because which one means NEW is a fact about a library and nothing in the call says
	// it (ADR-011).
	OnInsert []string
	OnUpdate []string

	// SubjectFields are the columns that say WHO a credential on this record admits, or
	// WHERE it is delivered. Changing one of these retargets the credential; changing a
	// status or a sort order does not, and a rule that reported every update leaving a
	// token alone would report almost every update there is.
	//
	// Declared rather than derived, and short on purpose. These are the fields a
	// verification link is ABOUT: healthchecks' fixed weakness is a channel whose address
	// changed while its token did not, and documenso's is a recipient's.
	SubjectFields []string

	CWE       string
	Finding   string
	Reason    string
	Rationale string
}

// GuardRule is a weakness in the SHAPE OF THE GRAPH rather than in a call, a value or a
// comparison: a rejection the program wrote and then walked past.
//
// It needs no declared expectation, which is the whole reason it is worth having. The
// program has already said in its own code that this request should not proceed; the only
// question left is whether it does.
type GuardRule struct {
	ID string
	// LateFileMode identifies a file created with the process umask, written, and only
	// then restricted. The three events are individually ordinary; their order and their
	// shared path/handle are the weakness.
	LateFileMode *LateFileModeGuard
	// Limiter turns this graph rule into a judgement about a control's attachment to
	// entry points. The call that increments a bucket is evidence that the application
	// HAS a limiter; the mount and predicates say which requests it governs. Keeping the
	// two together is what prevents this analysis becoming a universal complaint that a
	// route has no throttle.
	Limiter *LimiterGuard
	// RejectMethod names the calls that write a refusal into the response, and
	// RejectStatus the leading digits of a status that IS one. `res.status(400)` refuses;
	// `res.status(201)` is the happy path and says nothing about anything.
	//
	// A redirect is deliberately absent. `res.redirect(next)` after a successful login is
	// the same call as `res.redirect("/login")` after a failed one, and one production
	// repository writes eight of the first kind in a single function.
	RejectMethod []string
	RejectStatus []string
	// Raises names calls that end the request by throwing. Flask's `abort` is the one
	// that matters; the rest are found by looking at the function rather than the name.
	Raises []string

	// The second shape this kind reads, and the same judgement asked about a callback
	// rather than about a block: not "does work follow this refusal" but "will the thing
	// that produced the input be asked for more".
	//
	// A refusal inside a listener is not a refusal. `return` ends this invocation and the
	// next chunk arrives anyway, and rejecting a promise that is already rejected does
	// nothing at all -- so a size limit written this way is a limit the program checks
	// and then declines to enforce, while the buffer it was about keeps growing.
	//
	//	req.on("data", (chunk) => {
	//	  chunks.push(chunk)                                  // still runs
	//	  total += chunk.length
	//	  if (total > limit) reject(new Error("Too Large"))    // and nothing detaches this
	//	})
	//
	// Attaches names the calls that register a callback for an event and Repeats the
	// event names whose callback is called more than once -- both are lists because an
	// event's name is the only thing that says whether it happens again, and `end` and
	// `error` happen once. Refuses is what a refusal looks like where there is no
	// response object to write a status into. Accumulates names the calls that make the
	// invocation cost something that outlasts it. Detaches names what makes the refusal
	// real: removing the listener, or stopping what feeds it.
	Attaches    []string
	Repeats     []string
	Refuses     []string
	Accumulates []string
	Detaches    []string

	// The third shape, and the only one that judges a line against its SIBLING rather
	// than against the graph beneath it.
	//
	//	if mode not in ('navigate', 'cors'):
	//	    return flask.redirect(url_for('index'))    # this branch refuses
	//	if site not in ('same-origin', 'none'):
	//	    flask.redirect(url_for('index'))           # and this one builds the same
	//	                                               # refusal and drops it
	//
	// Constructs names the calls that BUILD a response instead of sending one. The
	// distinction is the whole rule: `res.status(403).json(...)` has already answered the
	// request by the time it returns, so discarding what it hands back costs nothing,
	// while `flask.redirect(...)` is a constructor -- it writes nothing, touches nothing,
	// and a caller who does not return it has written a line that does not exist.
	//
	// Naming those calls is not enough on its own, because a constructor called for
	// effect might simply be dead code somebody left behind. What makes this a weakness
	// is the sibling: the SAME construction, in the SAME function, returned. The program
	// has said in its own code what this branch was supposed to do, which is the only
	// ground the engine ever has for saying a line is missing.
	Constructs []string

	// The fourth shape, and the only one in this kind that judges a function against
	// ANOTHER function rather than against its own graph.
	//
	// Two handlers on one resource read the same value out of the request. One of them
	// asks a question about it and the other does not:
	//
	//	const { projectId, featureName } = req.params
	//	await this.featureService.validateFeatureBelongsToProject({ featureName, projectId })   // the read path
	//	...
	//	const { projectId, featureName } = req.params
	//	await this.featureService.updateVariantsOnEnv(featureName, projectId, ...)              // the write path
	//
	// The engine cannot know what check OUGHT to be there. What it can observe is that
	// the program performs one on a neighbouring path, over the very same value, and that
	// this path does not -- which is the same reasoning convention analysis uses when it
	// judges an entry point against its peers, narrowed from a population to a pair.
	//
	// Checks names the stems of a call that ASKS something; Retrieves the prefixes that
	// disqualify a name from being one, because `getPermissionsForUser` fetches where
	// `hasPermission` judges. Reads and Mutates name the prefixes that say which
	// direction a handler runs in, and the rule fires in ONE direction only: a check the
	// READ path makes and the WRITE path beside it does not. That is deliberate and it is
	// what makes the rule quiet. A write that checks more than a read is the ordinary
	// asymmetry of every application ever written and is evidence of nothing; a read that
	// checks more than a write is that asymmetry INVERTED, which no design explains.
	//
	// Records names the calls that merely write a value down. A value whose only visible
	// use is a log line was not operated on, so there is nothing a missing check would
	// have protected. Containers names the parameters that hold a request, because a
	// value with no request under it is not something a caller chose.
	//
	// Establishes names the parts of a request the SERVER wrote onto it. The comparison
	// is anchored on ONE value the caller picked to name a resource, and an identity the
	// authentication layer installed is not one: `request.user` is that layer's answer
	// about who is calling, so a handler consulting it has named no resource and a
	// handler that does not consult it has skipped nothing the caller could choose.
	Checks      []string
	Retrieves   []string
	Reads       []string
	Mutates     []string
	Records     []string
	Containers  []string
	Establishes []string

	// The fifth shape, and the only one that asks about a control's COVERAGE rather than
	// about a control's absence. Everything above reads a refusal that was written and
	// then walked past; this reads one that was written on one way in and not on the way
	// in beside it, where both ways end at the same operation on the same record.
	Omits *OmittedControlGuard

	// The sixth shape, and the same hole read from the other end: not an operation the
	// control does not stand on, but an exit the control's own APPLICATION is not
	// reachable from, taken from a path on which it was already being built.
	Discards *DiscardedRestrictionGuard

	CWE       string
	Finding   string
	Reason    string
	Rationale string
}

// OmittedControlGuard is the vocabulary for a control the program applies unevenly. The
// analyzer supplies the graph relation -- which paths reach the operation, and which of
// them the check stands on -- and this states only what a decision, a bookkeeping call
// and a reshaping call are called.
type OmittedControlGuard struct {
	// Decides names the stems of a call that DECIDES whether this caller may have this
	// record. Deliberately narrower than the sibling differential's Checks: that rule
	// compares a pair whose direction is known and can afford `validate` and `verify`,
	// while this one fires wherever two paths converge and would otherwise report every
	// input-validation asymmetry in a program.
	Decides []string
	// Retrieves are the prefixes that disqualify a name from being a decision, because
	// `getPermissionsForUser` fetches where `hasPermission` judges.
	Retrieves []string
	// Records names the calls that only write a value down. Logging a record is not
	// operating on it, so there is nothing a missing check would have protected.
	Records []string
	// Inert names the calls that reshape a value and act on nothing: a finding that
	// pointed at `json.dumps(event)` would name the wrong line, because the operation is
	// what the reshaped value was then handed to.
	Inert []string
}

// DiscardedRestrictionGuard is the vocabulary for a restriction a function builds and then
// leaves behind. The analyzer supplies the graph relation -- which exits are reachable
// from an append and which of them the application is not reachable from -- and this
// states only what adding, complaining, and restricting are called.
type DiscardedRestrictionGuard struct {
	// Appends names the calls that add to a collection.
	Appends []string
	// Restricts names the words that say the collection being built NARROWS something,
	// found on the function that builds it or on the collection itself. The engine cannot
	// know what an array of things is for, and this is the program's own statement of it;
	// without it the rule would report every accumulator in every codebase.
	Restricts []string
	// Records names the diagnostic calls. A complaint in the exiting block is what
	// separates failing open from a deliberate allow: medplum's own function returns
	// early twice out of the same loop over the same accumulator, and the difference
	// between the bug and the design is that one of them says something is wrong first.
	Records []string
}

// LateFileModeGuard is the vocabulary for one file lifecycle. The analyzer supplies
// aliasing and control-flow order; the model states the APIs and the final private mode.
type LateFileModeGuard struct {
	OpenSymbols  []string
	WriteMethods []string
	ChmodSymbols []string
	PrivateMode  int
}

// LimiterGuard describes rate limiting as a control rather than as a dangerous call.
// Every field is framework vocabulary; the guard engine supplies the graph relation.
type LimiterGuard struct {
	Framework string

	// Counters are calls that consume a bucket. Compared by full symbol or final segment
	// so an application wrapper and the imported spelling carry the same identity.
	Counters []string
	// Constructors create middleware whose bucket key is decided by its options.
	Constructors []string
	// MountMethods attach the control to an application or router.
	MountMethods []string

	// PathAttributes are request properties whose literal comparisons narrow a mounted
	// control to a route. RequestAttributes retain transport semantics: Flask args is
	// query-only, form is body-only, and values is the framework's merged view.
	PathAttributes    []string
	RequestAttributes []RequestAttribute

	// ExpensiveChannels are existing channel identities whose execution makes an
	// uncovered route consequential. URLMethods cover application wrappers that accept a
	// written URL and eventually perform the request under a project-specific symbol.
	ExpensiveChannels []string
	URLMethods        []string

	BucketKey *BucketKeyRule
	// KeyFromHeader is the same weakness read from the other end. BucketKey above asks
	// what a limiter's DEFAULT key becomes under a trust setting the application
	// declared; this asks what an application WROTE when it supplied a key of its own.
	KeyFromHeader *KeyFromHeaderRule
}

type RequestAttribute struct {
	Path      string
	Transport string // "query" | "body" | "query-or-body"
}

// KeyFromHeaderRule states when a limiter's bucket key is derived from a header the
// CALLER writes, rather than from the connection the caller opened.
//
// BucketKeyRule beside it reads the same weakness through configuration: a default
// `req.ip` key, plus `app.set("trust proxy", true)`, plus the limiter's own validation
// switched off. Those three facts are express-rate-limit's spelling of it, and unleash is
// where the engine found it -- reported as GHSA-2g9c-pxxc-3hq7.
//
// That rule keys on the LIBRARY and on a framework setting. Neither is present in an
// application that writes its own key: reactive-resume builds
// `ip:${headers.get("X-Forwarded-For").split(",")[0]}`, has no Express `trust proxy`
// anywhere, and its limiter comes from a package the list has never heard of. The
// weakness is identical -- vary the header, get a fresh bucket -- and the rule beside
// this one could not see it, because it was written about a configuration rather than
// about the key.
//
// So this states the key instead. Three facts, all read off the graph:
//
//   - a module CONSTRUCTS a rate limiter, by a word in the name of the call. `csurf`
//     and `csrfProtection` are matched the same way and for the same reason: every
//     spelling a project uses contains the word, and an exact list is wrong at the
//     next library.
//   - a function in it is the limiter's KEY, by the option it was written under. Both
//     frontends name an inline function after the property it is assigned to, so
//     `key: ({context}) => ...` lowers to a function called `key`.
//   - that function reaches a read of a FORWARDING header.
//
// The stated cost: a deployment whose proxy overwrites the header rather than appending
// to it has a trustworthy value here, and no static reading can tell the two apart. It
// is the same irreducible uncertainty the configuration rule accepts, and this rule
// carries one piece of evidence that one does not -- an application is free to read
// `X-Forwarded-For` for a log line or an audit field, and a value read into the thing
// that DECIDES a bucket is being trusted rather than recorded.
type KeyFromHeaderRule struct {
	// Vocabulary are the words that make a call the construction of a rate limiter.
	// Compared against the callee name with case and separators removed, so
	// `createRatelimitMiddleware`, `new MemoryRatelimiter`, `rateLimit` and
	// `RateLimiterRedis` are one word and four spellings.
	Vocabulary []string
	// KeyOptions are the option names a limiter's key function is written under.
	KeyOptions []string
	// ForwardingHeaders are the headers that convey a client address across a proxy.
	// Every one of them is written by whoever is upstream of the application, which on
	// a direct connection is the caller.
	//
	// Deliberately only these. `X-Account-ID` is caller-supplied too and is not here:
	// a key naming an ACCOUNT is a key the application means to trust, and whether it
	// is authenticated is a different question with a different answer. These headers
	// exist to carry an address the transport already knows, which is what makes
	// believing them a mistake rather than a design.
	ForwardingHeaders []string
}

// BucketKeyRule states when a limiter's default key is derived from configuration the
// application itself has declared trusted.
type BucketKeyRule struct {
	Default        string
	OverrideOption string
	Validation     string
	ValidationOff  string
	TrustMethod    string
	TrustKey       string
	TrustedValues  []string
}

// ScopeRule is a weakness in the RELATION between two calls: which key an authorization
// check was scoped to, and which key the operation it admitted was performed with.
//
// It is a rule kind of its own because nothing already here can say it. A channel says
// what a destination interprets and a policy says which class must not reach it; both are
// judgements about ONE value arriving at ONE place. This judgement has no such shape --
// the value that reaches the store is perfectly ordinary, and what makes it a defect is
// that the check standing in front of it asked about a DIFFERENT one. Two calls, a
// control-flow relation between them, and a comparison of the keys they carry.
//
// The alternative was a presumption, and the engine had it: "a helper receiving actor
// identity is presumed to enforce". That presumption is what a scoped-elsewhere handler
// satisfies -- the permission call is right there, carrying `req.user`, and it is
// authorizing something else.
type ScopeRule struct {
	ID string
	// IdentityClass is the classification whose presence in a call's arguments makes
	// that call an authorization check rather than an ordinary one.
	IdentityClass string

	// KeyWords are the trailing words that make a request field an IDENTIFIER rather
	// than a payload. Compared against the LAST word of the field's name, split on
	// camel case and underscores: `projectId`, `strategy_id` and `segmentIds` are
	// keys, `name` and `description` are not.
	//
	// A name list, and the narrowest form this project allows: it decides nothing about
	// a local variable, only about a field read off the request the handler was given.
	//
	// Two stated costs, both measured. A key spelled as a NAME is missed -- unleash's
	// `featureName` selects a feature -- because `name` is what most payload fields are
	// called. A key spelled as a SLUG was tried and withdrawn: a slug is a record's own
	// vanity string at least as often as it is a reference to another record, and
	// umami's link and pixel rename endpoints, whose whole purpose is to set the row's
	// own slug behind a unique constraint, were two of the four findings it produced.
	KeyWords []string

	// Mutations are the leading words that make a call a write to a store record that
	// ALREADY EXISTS. Two exclusions do the work here and both were measured.
	//
	// A read outside the authorized scope is worth knowing about and is not what this
	// rule reports; the operations named here are the ones that change something.
	//
	// A CREATE is excluded for a sharper reason: the identifiers a create is handed are
	// the new row's own fields, not a selector reaching an existing row, so the relation
	// this rule states does not apply to them. Three of the first five findings on real
	// code were `createLink({id: body.id ?? uuid()})` and its siblings -- a caller
	// choosing the primary key of a record it is creating, which may well be worth a
	// line and is not this one.
	Mutations []string

	// Selects are the leading words that make a call an operation on a record that
	// ALREADY EXISTS, in either direction. The accessor relation uses this where the key
	// relation uses Mutations, because there the operation word carries most of the
	// narrowing and here it carries almost none: what narrows the accessor relation is
	// that a check interrogated one accessor of a context and the operation went through
	// another one. Measured across ten production repositories, the read words in this
	// list added no finding the write words had not already produced.
	Selects []string

	// ChosenContainers are the request containers whose contents the CALLER decided.
	// A key taken from one of these is not a scope: being told which project to check
	// the caller against is not authorization, it is a parameter. A key from the route
	// or from established identity is, because the route is what the request addressed.
	ChosenContainers []string

	// Authorizes are the words that make a call an authorization QUESTION when it was
	// handed no identity value to ask about. Its presence selects the other relation
	// this analysis can state -- between the accessor a check interrogated and the
	// accessor an operation went through -- and its absence leaves the rule on the
	// relation between two request keys.
	//
	// A name list, and it has to be one. In the key relation, what makes a call an
	// authorization question is that the caller's identity was handed to it; here
	// nothing is handed over at all, because the identity is already inside the object
	// being asked -- `ctx.repo.isProjectAdmin()` takes no arguments and is the whole
	// check. With no value to recognise, the name is the only evidence left, and a
	// rule that accepted any boolean-returning guard would read `if (!cache.has(k))`
	// as an authorization.
	//
	// Matched against WORDS of the method name, split on camel case, so `isProjectAdmin`
	// and `is_project_admin` are one name and `administer` is not `admin`.
	Authorizes []string

	// Requires are the capabilities this rule needs. Deciding that a check GATES the
	// operation rather than merely preceding it is a control-flow question.
	Requires Requirements

	// Declared, when set, reads the rule's two operands out of a view's DECLARATIONS
	// instead of out of its control-flow graph. The relation being stated is identical --
	// a gate scoped to one key admitting an operation on another -- and the fields above
	// have nothing to match on, because a declarative view has neither call in it
	// (ADR-016: a rule that needs different operands is a field, not a new kind).
	Declared *DeclaredScope

	CWE       string
	Finding   string
	Reason    string
	Rationale string
}

// DeclaredScope selects which frameworks' declarations the scope relation is read from.
//
// Named rather than left implicit, because a declaration means what its framework says it
// means: `queryset` plus a lookup key is a record selection in DRF and could be anything
// at all in the next framework whose views get lowered. A rule that applied to whatever
// the frontend happened to emit would be making a claim nobody measured (ADR-004).
type DeclaredScope struct {
	Frameworks []string

	// BodyReason and BodyRationale say the same thing about the half of the rule where
	// the operation IS a call the application wrote. One weakness, two sentences, because
	// a reader looking at a bulk delete needs to be told that the check they cannot see
	// happened above the method rather than that a framework resolved something.
	BodyReason    string
	BodyRationale string
}

func builtinScopes() []ScopeRule {
	return []ScopeRule{
		{
			ID:            "authorization-scoped-elsewhere",
			IdentityClass: "actor-identity",
			KeyWords:      []string{"id", "ids", "uuid", "guid"},
			Mutations: []string{
				"update", "delete", "remove", "destroy", "patch", "archive",
				"restore", "rename", "revoke", "disable", "detach", "unlink",
				"move",
			},
			ChosenContainers: []string{"body", "data", "payload", "json", "form"},
			Requires:         Requirements{ControlFlow: true},
			CWE:              "CWE-639",
			Finding:          "Authorization scoped to a different record",
			Reason:           "the handler proved the caller may act on one record and then wrote to another one the caller also chose, with nothing relating the two",
			Rationale:        "a store write whose key was never the key the permission check asked about",
		},
		{
			// The same relation with the other operand. The rule above can only relate
			// two REQUEST keys, and the shape it cannot state is the one where the
			// caller's scope was never a request key at all: the authentication layer
			// established it, the handler holds it in a context object, and the check it
			// makes is `am I allowed here` rather than `am I allowed on THIS`.
			//
			//	if (!ctx.repo.isSuperAdmin() && !ctx.repo.isProjectAdmin())
			//	    return [forbidden];                      // asked ctx.repo
			//	const systemRepo = ctx.systemRepo;           // used ctx.systemRepo
			//	await systemRepo.withTransaction(async (txRepo) => {
			//	    let app = await txRepo.readResource('ClientApplication', req.params.id);
			//	    app = await txRepo.updateResource({...app, secret: generateSecret(32)});
			//
			// Two accessors hang off one context. One of them answered the permission
			// question and the other performed the operation, so whatever the first one's
			// answer was scoped to, the second one does not carry -- and the record it
			// reaches was named by the caller. That is medplum's rotate-secret handler,
			// where `ctx.repo` is bound to the caller's project and `ctx.systemRepo` is
			// constructed with `superAdmin: true`, and a project administrator of any
			// project can rotate and read back the secret of any client application.
			//
			// Nothing here knows which accessor is the privileged one and nothing needs
			// to: the defect is the SWAP. A handler that asks and acts through the same
			// accessor is silent whichever one it picked, and the one that asks about A
			// and acts through B has proved nothing about B whichever way the privilege
			// runs.
			//
			// The two rules partition rather than overlap: this one requires the check to
			// have been handed no request key, which is exactly the case the rule above
			// declines with "a check handed no key at all is not scoped to a record".
			ID: "authorization-through-a-different-accessor",
			// Names what the finding is ABOUT, and is not a precondition here. The rule
			// above declines any program where no identity source exists, because it has
			// nothing to recognise a check by; this one recognises the check by its
			// receiver and its name, so it still speaks where the engine has no rule for
			// the framework's identity. medplum is exactly that program -- `no source for
			// actor-identity in this program` is the engine's own verdict on it, and the
			// finding this rule reports there is the only one any ownership judgement
			// makes in the whole repository.
			IdentityClass: "actor-identity",
			KeyWords:      []string{"id", "ids", "uuid", "guid"},
			// Reads AND writes, where the rule above is writes only, and the widening
			// was measured before it was written down (ADR-015).
			//
			// The rule above excludes reads because a read outside the authorized scope
			// is a different claim, and that exclusion is what keeps it quiet. Here the
			// same widening costs nothing: adding all eleven read words to this list
			// produced ZERO additional findings across the ten production repositories
			// this engine is measured on. It moved the one finding it has -- from the
			// update on line 58 of medplum's rotate-secret handler to the read on line 56
			// that fetched the record for it. The accessor swap is doing the narrowing,
			// so the operation word narrows almost nothing on top of it.
			//
			// A read is also the whole weakness for the shape this rule exists to catch.
			// A handler that fetches another tenant's row through an accessor nobody
			// asked about has disclosed it; whether it went on to write is incidental.
			Selects: []string{
				"update", "delete", "remove", "destroy", "patch", "archive",
				"restore", "rename", "revoke", "disable", "detach", "unlink", "move",
				"read", "get", "find", "fetch", "load", "select", "query", "list",
				"search", "view", "show",
			},
			Authorizes: []string{
				"admin", "superuser", "owner", "owns", "member", "staff",
				"permission", "permissions", "permitted", "authorized", "authorize",
				"allowed", "privileged", "role", "roles", "forbidden",
			},
			Requires:  Requirements{ControlFlow: true},
			CWE:       "CWE-639",
			Finding:   "Authorization asked one accessor and the operation used another",
			Reason:    "the handler asked one accessor of its request context whether the caller may act, and then acted through a different accessor of the same context on a record the caller named, so whatever the check established does not cover what the operation reached",
			Rationale: "a record operation performed through a sibling accessor of the context whose other accessor answered the permission check, keyed by a request field, with nothing relating that record to the caller's context",
		},
		{
			// The same relation where neither operand is a call.
			//
			// The rule above needs a gate call and an operation call in one control-flow
			// graph. A declaratively registered view has neither: `permission_classes`
			// and `queryset` are class attributes, the framework does the selecting, and
			// the class body an analysis would read is empty. That is not a rarity --
			// it is how every Django REST Framework detail view is written, and doccano
			// holds ten of them whose permission asks about `project_id` while the
			// framework fetches the row named by `example_id`, `tag_id` or `label_id`.
			//
			// Reads are reported here and are not reported by the rule above, and the
			// difference is a fact about the shape rather than a change of mind. A store
			// write is one call and the analysis can see which verb it is; a DRF detail
			// view resolves ONE record through `get_object()` and serves it to GET, PUT,
			// PATCH and DELETE alike, so there is no read to separate from the write --
			// the declaration is the same declaration. Four of the seven findings this
			// rule was built for are cross-project reads.
			//
			// Measured before it was written, over the seven Python repositories of the
			// clean corpus (ADR-015). wger declares 52 of these views and paperless-ngx
			// 71 registrations; neither produces a single match, because neither has a
			// permission class that consults a URL keyword -- they scope by the
			// requester in `get_queryset` instead, which is the shape this rule is
			// silent about by construction. Every match is in doccano: eleven distinct
			// declarations, all adjudicated true against source, while the other nine
			// production repositories report findings byte-identical to before.
			//
			// Widening the rule above to reads was measured as the alternative and does
			// not do this. Nineteen read verbs added to its `Mutations` changed not one
			// finding on any of the ten repositories, because what keeps it quiet on a
			// declarative view is the missing gate call rather than the verb list.
			//
			// The rule also judges the view's own handler bodies, and there the write
			// restriction comes back. A bulk delete written into `delete()` IS a call
			// with a verb to read, so the reason the rule above excludes reads applies
			// again unchanged -- what makes the declarative half different is that
			// `get_object()` has no verb of its own, not that reads became interesting.
			ID: "authorization-declared-elsewhere",
			Declared: &DeclaredScope{
				Frameworks:    []string{"drf"},
				BodyReason:    "the view's authorization is declared against one request key and this method operates on a record the caller named with another, and the class relates them nowhere",
				BodyRationale: "a store write under a declared permission, keyed by a request field that permission never asks about",
			},
			Requires: Requirements{FrameworkModels: []string{"drf"}},
			// Not what makes a call a check here -- the check is declared and there is no
			// call. It is read for the other direction: an operation narrowed by the
			// REQUESTER is related to the requester, and a bulk delete written
			// `filter(user=request.user, pk__in=ids)` cannot reach a row its caller does
			// not own however many keys it also carries.
			IdentityClass: "actor-identity",
			KeyWords:      []string{"id", "ids", "uuid", "guid"},
			Mutations: []string{
				"update", "delete", "remove", "destroy", "patch", "archive",
				"restore", "rename", "revoke", "disable", "detach", "unlink",
				"move",
			},
			CWE:       "CWE-639",
			Finding:   "Authorization declared for a different record",
			Reason:    "the view's authorization is declared against one request key and the framework resolves the record from another, and the view declares nothing relating them",
			Rationale: "a framework-resolved record selection whose key was never the key the declared permission asks about",
		},
	}
}

func builtinGuards() []GuardRule {
	return []GuardRule{
		{
			ID: "secret-file-created-before-chmod",
			LateFileMode: &LateFileModeGuard{
				OpenSymbols:  []string{"builtins.open"},
				WriteMethods: []string{"write", "writelines"},
				ChmodSymbols: []string{"os.chmod"},
				PrivateMode:  0o600,
			},
			CWE:       "CWE-732",
			Finding:   "Secret file created before its mode is restricted",
			Reason:    "the file exists at the process umask while secret data is written, so another local user can read it before the later chmod narrows access",
			Rationale: "the same path is opened for creation, written through that handle, and only afterwards chmodded to 0o600",
		},
		{
			ID: "expensive-entry-outside-rate-limiter",
			Limiter: &LimiterGuard{
				Framework:      "flask",
				Counters:       []string{"incr_sliding_window"},
				MountMethods:   []string{"before_request"},
				PathAttributes: []string{"path"},
				RequestAttributes: []RequestAttribute{
					{Path: "args", Transport: "query"},
					{Path: "form", Transport: "body"},
					{Path: "values", Transport: "query-or-body"},
				},
				ExpensiveChannels: []string{"outbound-destination", "outbound-http", "shell-command", "sql-query"},
				URLMethods:        []string{"get", "post", "put", "patch", "delete", "request", "urlopen"},
			},
			CWE:       "CWE-770",
			Finding:   "An expensive entry point is outside the application's rate limiter",
			Reason:    "the application mounts a rate limiter, but its own route predicate excludes this entry point before the bucket is consumed",
			Rationale: "a mounted limiter consumes a bucket only under a request predicate that this expensive entry point does not satisfy",
		},
		{
			ID: "rate-limit-key-from-trusted-forwarding-header",
			Limiter: &LimiterGuard{
				Framework:    "express",
				Constructors: []string{"express-rate-limit.default"},
				BucketKey: &BucketKeyRule{
					Default:        "req.ip",
					OverrideOption: "keyGenerator",
					Validation:     "validate",
					ValidationOff:  "false",
					TrustMethod:    "set",
					TrustKey:       "trust proxy",
					TrustedValues:  []string{"true"},
				},
			},
			CWE:       "CWE-770",
			Finding:   "The rate-limit bucket key trusts a client-supplied forwarding chain",
			Reason:    "the limiter uses its default req.ip key while the application trusts every proxy hop and has disabled the limiter's validation of that configuration",
			Rationale: "the application configures forwarded addresses as trusted and leaves the limiter bucket keyed by the resulting request IP",
		},
		{
			// The same weakness where the application supplies the key itself. The rule
			// above reads a configuration -- express-rate-limit's default key under
			// `trust proxy` -- and found it in unleash, adjudicated true and reported as
			// GHSA-2g9c-pxxc-3hq7. It is silent on an application that writes its own
			// key, because neither the library nor the framework setting it names is
			// there to match: reactive-resume's limiter comes from a package this list
			// has never heard of, sets no Express trust anywhere, and reads
			// `X-Forwarded-For` straight out of the request headers. Varying the header
			// makes a new bucket, which is exactly what the rule above exists to say.
			ID: "rate-limit-key-from-a-client-supplied-header",
			Limiter: &LimiterGuard{
				KeyFromHeader: &KeyFromHeaderRule{
					Vocabulary: []string{"ratelimit", "throttle", "slowdown", "limiter"},
					KeyOptions: []string{"key", "keyGenerator", "keyFn", "getKey"},
					// The headers a proxy writes to carry the address the transport
					// already knows. On a direct connection there is no proxy and the
					// caller writes them.
					ForwardingHeaders: []string{
						"x-forwarded-for", "x-real-ip", "x-client-ip", "x-cluster-client-ip",
						"cf-connecting-ip", "cf-connecting-ipv6", "true-client-ip",
						"fastly-client-ip", "x-forwarded", "forwarded-for", "forwarded",
					},
				},
			},
			CWE:       "CWE-770",
			Finding:   "The rate-limit bucket key is a header the caller writes",
			Reason:    "the value the limiter counts against is read out of a forwarding header, and anyone can send a different one, so each request can land in a bucket of its own",
			Rationale: "a function supplied as a rate limiter's key reads a header that conveys a client address, which the caller supplies on any connection that is not behind a proxy overwriting it",
		},
		{
			ID:           "rejection-without-return",
			RejectMethod: []string{"status", "sendStatus", "status_code"},
			RejectStatus: []string{"4", "5"},
			Raises:       []string{"abort", "fail"},
			CWE:          "CWE-698",
			Finding:      "The handler refuses the request and carries on",
			Reason:       "the program has already decided this request should not proceed, and the operation it was refusing runs anyway -- so the refusal is a status code and nothing more",
			Rationale:    "an error status is written into the response and work that follows it is unavoidable",
		},
		{
			// The same judgement about a callback rather than a block. A size limit
			// enforced from inside a `data` listener is a limit the program measures and
			// then does not apply: the listener stays attached, the next chunk is pushed
			// onto the same array, and the promise it rejected is already rejected.
			//
			// The three lists are what keep this from being a rule about promises. An
			// event that happens ONCE needs no detaching, so the event name decides
			// whether there is a weakness at all; a callback that accumulates nothing
			// costs nothing to run again; and a listener something removes, or a source
			// something destroys, is a refusal that took effect.
			ID:          "refusal-inside-a-repeating-callback",
			Attaches:    []string{"on", "addListener", "prependListener", "addEventListener"},
			Repeats:     []string{"data", "chunk", "message", "readable", "packet", "frame"},
			Refuses:     []string{"reject", "abort", "fail"},
			Accumulates: []string{"push", "append", "concat", "write", "add", "extend", "set"},
			Detaches: []string{
				"destroy", "removeListener", "removeAllListeners", "off", "pause",
				"unpipe", "abort", "close", "end", "unsubscribe", "detach", "cancel",
			},
			CWE:     "CWE-770",
			Finding: "The program refused the input and goes on accepting it",
			Reason:  "the refusal is written inside a callback the source will call again, and nothing removes the callback or stops the source, so the next chunk is appended to the very buffer the limit was about",
			Rationale: "a refusal inside a listener registered for a repeating event, in a callback that appends to a collection it did not create, " +
				"with nothing on any path detaching the listener or stopping what feeds it",
		},
		{
			// A refusal the program constructed and then let fall on the floor, judged
			// against the branch beside it that returns the identical construction.
			//
			// The list is response CONSTRUCTORS and nothing else. Every one of these
			// builds an object and does not send it, so its result is the only thing it
			// produces -- which is what makes discarding it a line that does nothing at
			// all, rather than a matter of style. `res.redirect()` and `self.redirect()`
			// are deliberately absent for the same reason the rejection rule above
			// excludes a redirect: those SEND, and whether the caller kept what they
			// handed back says nothing about anything.
			ID: "rejection-built-and-discarded",
			Constructs: []string{
				"redirect", "make_response", "jsonify", "json_response",
				"HttpResponseRedirect", "HttpResponseForbidden", "HttpResponseBadRequest",
				"HttpResponseNotFound", "HttpResponseNotAllowed", "HttpResponseGone",
				"JsonResponse",
			},
			CWE:       "CWE-698",
			Finding:   "The handler builds a refusal and drops it",
			Reason:    "the branch beside this one returns the very same construction, and this one leaves it on the floor -- so the check runs, decides against the request, and the request proceeds",
			Rationale: "a response constructor whose result is used nowhere, where another call to the same constructor in the same function is returned",
		},
		{
			// A check one handler makes and the handler beside it does not, over the same
			// value out of the same request.
			//
			// Every list here is a narrowing that was measured rather than guessed. The
			// loosest form of this comparison -- "the guard sets differ" -- produced 32
			// candidate pairs in a single repository, almost all of them a read path that
			// does not do what a write path does, which is what correct code looks like.
			// Four conditions cut that to three, and the three are one weakness:
			//
			//   the value is one the CALLER chose, read off a request parameter;
			//   the direction is inverted, a check on the READ path and not the write;
			//   the weak path holds every value the check consumed, because a check it
			//     has no arguments for is a different question, not a missing one;
			//   the weak path does something with the value other than log it.
			//
			// The first of those four was stated here and not enforced: the analysis
			// accepted the request CONTAINER and every attribute of it as the value, and
			// seven findings across ten production repositories were exactly what that
			// admits. An independent reader judged none of them worth reporting. Three
			// were saleor's graphql/context.py, where the three functions that BUILD the
			// request's identity were compared against the get_user that reads it over
			// `request` itself -- `authenticate(request=request)` read as an authorization
			// guard those three had skipped, when a function that PRODUCES the identity
			// cannot be required to have already consumed it. Four were paperless-ngx,
			// anchored on `request.user`, which is the framework's answer about who is
			// calling rather than anything a caller picked. Establishes names that second
			// shape; the container is refused outright, because it is not a value at all.
			ID:        "sibling-guard-differential",
			Checks:    []string{"validate", "verify", "authoriz", "authenticat", "permission", "permitted", "allowed", "hasaccess", "canaccess", "checkaccess", "belongsto", "isowner", "owns", "forbidden"},
			Retrieves: []string{"get", "fetch", "find", "list", "load", "read", "select", "query"},
			Reads:     []string{"get", "list", "fetch", "find", "read", "search", "show", "index", "count", "query", "view", "load", "describe"},
			Mutates: []string{
				"create", "update", "delete", "remove", "patch", "put", "post", "add",
				"set", "save", "overwrite", "push", "insert", "upsert", "archive",
				"restore", "rename", "revoke", "disable", "enable", "move", "clone",
				"register", "import", "reset", "change", "toggle", "assign", "apply",
				"write", "edit", "bulk",
			},
			Records:    []string{"log", "logger", "debug", "info", "warn", "warning", "error", "trace", "console", "print"},
			Containers: []string{"req", "request", "ctx", "context"},
			// What an authentication layer hangs on a request, in the four spellings the
			// corpus holds: Django and DRF's `request.user` and `request.auth`, saleor's
			// `request.app`, and the session every framework keys off a cookie. Not
			// `cookies` and not `headers` -- the caller writes both of those.
			Establishes: []string{"user", "auth", "app", "session"},
			CWE:         "CWE-862",
			Finding:     "A check the sibling path makes and this one does not",
			Reason:      "the read path on this resource asks whether the caller's value is the one it claims to be, and this write path takes the same value out of the same request and does not ask",
			Rationale:   "a request value a sibling read path passes to a validation or authorization call, used here by a write path that passes it to no such call",
		},
		{
			// A control the program HAS, applied on one path and not on the path beside
			// it, where both paths end at the same operation on the same record.
			//
			// The convention analysis already reports an entry point missing what its
			// peers apply and cannot tell a public route from a forgotten one -- medplum
			// mounts a public FHIR router beside a protected one deliberately, and the
			// CWE-306 rule reported it until the design said otherwise. What separates
			// this from that is CONVERGENCE: the two paths produce the same value and
			// hand it to the same call, so no design explains guarding one and not the
			// other. A public route beside a protected one shares no value and no sink
			// and is never paired.
			//
			// Decides is short on purpose. Measured on ten production repositories, the
			// stem list that also held `validate` and `verify` turned this into a report
			// on every handler that validates an input on one branch, which is what
			// correct code looks like; the access stems alone left the two real cases.
			ID: "control-omitted-on-sibling-path",
			Omits: &OmittedControlGuard{
				Decides: []string{
					"canview", "canaccess", "canread", "canedit", "canwrite", "candelete",
					"canmanage", "cansee", "canmodify", "canuse", "permission", "permitted",
					"authoriz", "hasaccess", "checkaccess", "isowner", "ownedby", "belongsto",
					"isallowed", "allowedto", "mayaccess", "accessible", "visibleto",
				},
				Retrieves: []string{"get", "fetch", "find", "list", "load", "read", "select", "query", "build", "make", "create"},
				Records:   []string{"log", "logger", "debug", "info", "warn", "warning", "error", "trace", "console", "print", "audit", "metric"},
				Inert: []string{
					"str", "int", "float", "bool", "len", "list", "dict", "set", "tuple",
					"dumps", "loads", "stringify", "parse", "format", "join", "split",
					"strip", "lower", "upper", "repr", "sorted", "reversed", "enumerate",
					"append", "push", "keys", "values", "items", "type",
				},
			},
			CWE:       "CWE-862",
			Finding:   "A control the path beside this one applies and this one does not",
			Reason:    "the program decides whether this caller may have this record on one way in, and the way in beside it reaches the same operation on the same record without deciding anything",
			Rationale: "an access decision that stands on one path to an operation, where another path defines the same value and reaches that operation with no decision on it",
		},
		{
			// A restriction the program built and then left behind: an exit taken from a
			// path that had already added to the accumulator, from which the point that
			// attaches it is not reachable. The function's only product is the effect, so
			// leaving without it does not narrow the query -- it widens it.
			//
			// Restricts is what keeps this from being a general dead-work rule: the
			// engine cannot know what an array is FOR, and the name the program builds it
			// under is the only statement of intent in the source. Records is what keeps
			// it from reporting a deliberate allow -- measured on medplum, the graph
			// alone cannot tell the invalid-criteria return from the no-criteria return
			// nine lines below it, and only one of them complains first.
			ID: "discarded-restriction",
			Discards: &DiscardedRestrictionGuard{
				Appends:   []string{"push", "append", "add", "extend", "insert", "concat"},
				Restricts: []string{"filter", "predicate", "criteria", "restrict", "scope", "permission", "access", "policy", "authoriz", "condition", "constraint", "where", "clause"},
				Records:   []string{"log", "logger", "warn", "warning", "error", "critical", "exception", "audit"},
			},
			CWE:       "CWE-636",
			Finding:   "A restriction built and abandoned on the way out",
			Reason:    "this function's only product is the restriction it attaches, and this branch leaves without attaching what it had already built -- so the query it was narrowing runs wide",
			Rationale: "an accumulated restriction, an exit reachable from the accumulation that the application is not reachable from, and a diagnostic in the exiting block saying the input was wrong",
		},
	}
}

func builtinStores() []StoreRule {
	return []StoreRule{
		{
			// Writing to `innerHTML` parses what it is given as markup. It is the
			// browser-side twin of an unescaped template interpolation and it needs no
			// call at all -- the assignment IS the parse, which is why a rule that
			// watches calls could not see it.
			//
			// `textContent` is deliberately absent: it is the same assignment with the
			// parsing turned off, and it is the fix.
			ID:        "markup-assignment",
			Class:     "untrusted-input",
			Path:      []string{"innerHTML", "outerHTML"},
			CWE:       "CWE-79",
			Finding:   "Caller's text assigned as markup",
			Reason:    "assigning to innerHTML parses what it is given as HTML, so a caller who sends a tag gets a tag",
			Rationale: "the value is written into a property the browser parses as markup",
		},
		{
			// A browser interprets these properties as URLs. Supplying the whole value is
			// a scheme decision, not an HTML-escaping decision: `javascript:` is still a
			// script URL after every quote and angle bracket has been escaped.
			ID: "untrusted-url-target", Class: "untrusted-input",
			Path:               []string{"href", "src", "action"},
			RequiresWholeValue: true,
			Context:            "url-target",
			CWE:                "CWE-79",
			Finding:            "Caller's URL assigned to a browser navigation target",
			Reason:             "the caller supplies the whole URL, so HTML escaping cannot stop a script-bearing scheme such as javascript or data",
			Rationale:          "the property is interpreted as a URL and no program-written prefix constrains its scheme",
		},
		{
			// With a fixed prefix the host and scheme are the program's, so this is not
			// SSRF. The syntax the caller can still choose is the URL component syntax:
			// a slash, question mark, fragment or dot segment changes the resource named.
			ID: "untrusted-url-part", Class: "untrusted-input",
			Path:                []string{"href", "src", "action"},
			RequiresComposition: true,
			Context:             "url-part",
			CWE:                 "CWE-116",
			Finding:             "Caller's text composed into a URL component",
			Reason:              "the caller's text is placed after a program-written URL prefix without URL-component encoding, so separators change the path, query or fragment",
			Rationale:           "the property is interpreted as a URL whose host is fixed but whose component syntax is not",
		},
		{
			// A session is server-side state, which is exactly what makes this worth
			// reporting: everything downstream reads it back as something the server
			// established, and by then the fact that a caller chose it is gone.
			// The class is a caller-asserted AUTHORITY, not caller input generally.
			// Sessions legitimately hold things the caller chose -- a return URL, a
			// pending registration, a theme -- and nodebb does exactly that twice. What
			// must not cross is a claim about what the caller is ALLOWED to do, because
			// that is what everything downstream reads back as established.
			ID: "untrusted-into-session", Class: "caller-asserted-authority", Into: []string{"session"},
			CWE:       "CWE-501",
			Finding:   "Caller's data written into the session",
			Reason:    "a session is read back as state the server established, so putting the caller's own data there launders it across the trust boundary and everything downstream believes it",
			Rationale: "the value written into the session came from the request",
		},
		{
			// A field the server owns, set from a field the caller sent. The classic is
			// the caller deciding their own role, and it is the same weakness whatever
			// the record is called -- so this rule names the FIELD and says nothing about
			// the object holding it.
			//
			// Distinct from mass assignment, which is the caller supplying keys nobody
			// enumerated. Here the application enumerated one, and picked the wrong one.
			ID: "caller-sets-own-privilege", Class: "caller-asserted-authority",
			Path:                authorityNames,
			RequiresUnprojected: true,
			// A session is the trust-boundary rule's subject and it reports the same
			// line under CWE-501, which says the sharper thing about it: what makes a
			// session dangerous is that everything downstream reads it back as
			// established, not merely that a privilege was written.
			NotInto:   []string{"session"},
			CWE:       "CWE-472",
			Finding:   "A privilege field set from the request",
			Reason:    "the value written decides what this account may do, and it arrived in a request the account holder wrote",
			Rationale: "a field naming a privilege was assigned from data the caller sent",
		},
		{
			// One request's data left where the next request finds it. A module-level
			// variable assigned inside a handler is shared by every caller the process
			// serves, so whatever was put there is answered to somebody else.
			//
			// The language rule is the evidence and there is no guessing in it: Python
			// needs the name declared `global` and JavaScript needs it bound in an
			// enclosing scope, and the same statement without either makes a local and
			// touches nothing.
			ID: "request-data-into-process-state", Class: "untrusted-input",
			IntoScope:             "process",
			RequiresEntryFunction: true,
			RequiresUnprojected:   true,
			CWE:                   "CWE-488",
			Finding:               "One request's data written into state the whole process shares",
			Reason:                "every request this process handles reads the same variable, so what one caller put there is what the next caller gets",
			Rationale:             "the assignment reaches a name bound outside the handler",
		},
		{
			// The same write the rule above declines to read, read the other way round.
			// That one asks what was PUT in a container; this one asks what it was put
			// UNDER, because the key is what decides how large the container can become:
			// one entry per distinct key, and a caller who chooses the keys has an
			// unlimited supply of them.
			//
			// Three things have to hold together and each removes a whole population of
			// ordinary code. The container has to outlive the request, or it dies with
			// the handler however much it grew. The key has to be the caller's, or the
			// number of keys is the program's business. And nothing may cap the
			// container, because a cache with an eviction bound is a cache.
			//
			// The fourth is what separates a leak from a memo, and it is the one that
			// makes the rule usable: a write that is on the far side of a branch on a
			// LOOKUP of the same key can only ever hold keys that name something real.
			// The number of real things is not the caller's to choose.
			ID:       "unbounded-retention-by-caller-key",
			KeyClass: "untrusted-input",
			// The process environment is a namespace with a meaning rather than a
			// container something is kept in, and a caller's value written into one is a
			// weakness the model already reports under its own number. Two rules
			// describing one line at different granularities is what NotInto is for, and
			// the narrower one keeps it. Measured: misskey's test harness has a route
			// that does exactly this, and across ten production repositories it was the
			// only other thing this rule had to say.
			NotInto:              []string{"env", "environ"},
			IntoOutlivingRequest: true,
			AbsentSizeBound:      true,
			NotAfterLookup:       true,
			// The language's own conversions and predicates. Every one of these answers
			// a question about the key's TEXT, and no answer about a key's text bounds
			// how many keys there can be.
			KeyPure: []string{
				"parseInt", "parseFloat", "Number", "String", "Boolean", "isNaN",
				"toString", "valueOf", "encodeURIComponent", "decodeURIComponent",
				"int", "str", "float", "bool", "len", "abs", "round",
			},
			RequiresEntryFunction: true,
			CWE:                   "CWE-770",
			Finding:               "The caller decides how many entries the process keeps",
			Reason:                "the container outlives the request and gains an entry per distinct key, the key is one the caller chose, and nothing in the program bounds how many there can be",
			Rationale:             "a write into state bound outside the handler, under a key the caller supplied, with no size bound anywhere and no lookup deciding the key names anything",
		},
		{
			// A credential that outlives the thing it admits. The record's own create
			// says a new one needs a fresh token; the update beside it rewrites the
			// address the token was issued for and leaves the token standing, so the
			// link that was mailed to the old address now admits its holder to the new
			// one.
			//
			// This is the healthchecks weakness -- the first this engine found in the
			// wild that a maintainer fixed -- stated as a WRITE rather than as a hash
			// seed. There the token was a digest of the channel's immutable id and the
			// server secret, so it could not depend on the address; here the token is
			// random and the same independence is achieved by not reissuing it. The
			// remedy is identical and so is the sentence: the credential does not cover
			// what it admits.
			//
			// Only the two-group form, and that is the whole of what makes an absence
			// decidable here without a population to compare against. A create in one
			// file and an update in another is the same defect and is NOT reported: over
			// ten production repositories that broader shape matches 173 calls, against
			// two for this one, and both of the two are the weakness.
			ID:            "credential-not-reissued-with-subject",
			OnInsert:      []string{"create", "$setoninsert", "defaults"},
			OnUpdate:      []string{"update", "$set"},
			SubjectFields: []string{"email", "address", "phone", "username", "recipient"},
			CWE:           "CWE-613",
			Finding:       "Credential left standing when the subject it admits changed",
			Reason:        "the record's own insert says a new one of these needs a freshly minted credential, and the update beside it rewrites the address that credential was issued for without reissuing it -- so a link sent to the old address admits its holder to the new one",
			Rationale:     "one call states what to write for a new record and what to write for an existing one",
		},
		{
			// A direct assignment to the session's principal slot is the low-level form of
			// an identity change. Application-owned namespaces are not: measured on wger,
			// `trainer.identity` and `gym.user` were the whole two-finding population and
			// both only stored data for later display.
			ID:    "session-not-rotated",
			Class: "identity-change",
			Into:  []string{"session"},
			// The keys that say WHO the session belongs to, or what it may do. A session
			// carries a shopping basket and a language preference too, and rewriting one
			// of those is not a change of principal.
			Path: []string{"userId", "user_id", "user", "uid", "accountId", "account_id",
				"isAdmin", "is_admin", "role", "roles", "authenticated", "isAuthenticated",
				"loggedIn", "logged_in", "auth", "principal", "identity", "username",
				"passport", "currentUser", "current_user", "_auth_user_id"},
			DirectPath: true,
			// `clear` is here because for a client-side signed cookie there is no
			// server-side identifier to rotate, and emptying the session before installing
			// the identity discards whatever an attacker planted in it. It is the same
			// remedy under a different storage model, and a rule about an absence has to
			// know every shape the presence takes.
			// Django's login call performs the cycle itself; Passport's login operation
			// likewise regenerates before serializing the user. They are identity-change
			// calls and rotation evidence at once, not arbitrary calls near a write.
			AbsentCall: []string{"regenerate", "regenerateId", "cycle", "cycle_key",
				"cycleKey", "reset", "clear"},
			IdentityCalls:            []string{"login", "django_login", "logIn"},
			IntrinsicRotationSymbols: []string{"django.contrib.auth.login"},
			IntrinsicRotationMethods: []string{"login", "logIn"},
			NotElement:               true,
			NotFrom:                  []string{"null", "undefined", "none", "false", "0", ""},
			CWE:                      "CWE-384",
			Finding:                  "Session identifier survives the change of identity",
			Reason:                   "an identifier an attacker planted or captured before the login still names the session after it, and that session is now the victim's",
			Rationale:                "the request's authenticated identity changes and no accompanying operation rotates the session identifier",
		},
		{
			// A signing key, a password or an API key written into a configuration
			// assignment. `app.config['SECRET_KEY'] = '...'` and `app.secret_key = '...'`
			// are how a Flask application is misconfigured, and the key is then in every
			// clone of the repository and in its history after somebody changes it.
			//
			// The identifier and value are a conjunction. A WORD in the key narrows what
			// the value is for, because configuration keys are compound and an exact list
			// is wrong at the first application that adds a suffix. The value must still
			// be capable of serving as the credential: healthchecks' measured
			// `email_password_status = "success"` is not. `csrf` is excluded for the
			// reason the cookie rules exclude it: a double-submit token contains the word
			// and is not a secret.
			ID: "hardcoded-secret", Class: "", FromLiteral: true, FromLiteralFallback: true,
			FromLiteralArgument: true,
			// No "token". Measured across twenty-eight repositories: every configuration key
			// holding that word held an OAuth endpoint URL, a header name or a form field,
			// and not one held a secret. The word names the THING a key is for far more
			// often than the key itself.
			PathContains: []string{"secret", "password", "passwd", "apikey", "api_key",
				"private_key", "privatekey", "signing_key", "signingkey"},
			PathExcept:       []string{"csrf", "xsrf", "public", "expire", "header", "name", "field"},
			PathExceptSuffix: []string{"id", "identifier"},
			CWE:              "CWE-798",
			Finding:          "Secret written into the source",
			Reason:           "a key in the source is in every clone of the repository and stays in its history after it is changed",
			Rationale:        "a configuration key that holds a secret is assigned a value written in the call",
		},
		{
			// The same judgement where the configuration namespace is a MODULE.
			//
			// The rule above matches a write into something -- `app.config["SECRET_KEY"]`,
			// `app.secret_key` -- because in Flask there is an object to write into. A
			// Django settings module has no object at all: `django.conf.settings.SECRET_KEY`
			// reads the module-level `SECRET_KEY` of whichever module the deployment names,
			// so the configuration write is a bare assignment and the rule above could not
			// see it. That is one of the two largest Python web frameworks having no
			// hardcoded-secret rule that applies to it, and doccano is the measured case:
			// `SECRET_KEY = env("SECRET_KEY", "v8sk33sy82!...")` at
			// backend/config/settings/base.py:29, the same fixed value in the shipped
			// Dockerfile, and a documented run command that supplies no key of its own.
			//
			// The credential words, the exclusions and the bar on the value are all the
			// same. What differs is only where the program keeps its configuration -- and
			// one thing more, stated because it was measured rather than chosen.
			//
			// FromLiteral is deliberately absent, so a module-level setting assigned a
			// PLAIN literal is not claimed here. Widened to include it, this rule reported
			// two lines in the engine's own corpus that no expectation names, and both
			// readings are instructive: `CATALOG_SECRET = "sk_live_..."` in
			// upstream-response is already reported by the literal analysis, which judges
			// the value's SHAPE, so the widening bought a second finding on one line; and
			// `_LINK_SECRET = "signing-secret-from-the-vault"` in
			// digest-compared-against-what is a real hardcoded secret in a fixture written
			// about something else, which is a true reading and still a corpus this rule
			// has no business changing. The recall cost is stated rather than hidden: a
			// module-level `X = "some-key"` whose value matches no provider shape is a
			// miss, and the case this rule exists for -- the value that becomes the
			// credential precisely when the deployment supplies nothing -- is the one no
			// other rule could see at all.
			ID: "hardcoded-secret", Class: "", IntoScope: "module",
			FromLiteralFallback: true, FromLiteralArgument: true,
			PathContains: []string{"secret", "password", "passwd", "apikey", "api_key",
				"private_key", "privatekey", "signing_key", "signingkey"},
			PathExcept:       []string{"csrf", "xsrf", "public", "expire", "header", "name", "field"},
			PathExceptSuffix: []string{"id", "identifier"},
			CWE:              "CWE-798",
			Finding:          "Secret written into the source",
			Reason:           "a key in the source is in every clone of the repository and stays in its history after it is changed",
			Rationale:        "a module-level setting that holds a secret is assigned a value written in the source",
		},
		{
			// A digest from a broken algorithm written into the field a login will later
			// be checked against. The comparison happens in another request and usually in
			// another function, so the flow that would show it is not there to follow --
			// but the write says the whole thing on its own: this digest is what the
			// account's password now IS, and anything hashing to it is that password.
			//
			// Named by the FIELD and silent about the object holding it, for the reason
			// the privilege rule is: enumerating what a user record can be called is a
			// list that is wrong at the first application that names one differently.
			ID: "weak-digest-as-credential", Class: "weak-digest",
			PathContains: []string{"password", "passwd", "pwhash", "pwd"},
			// A reset URL, a password POLICY and a confirmation field all carry the word
			// and none of them is a stored verifier.
			PathExcept:          []string{"policy", "url", "link", "reset", "confirm", "repeat", "csrf", "xsrf", "hint", "expire", "changed", "last"},
			RequiresUnprojected: true,
			CWE:                 "CWE-328",
			Finding:             "Broken digest stored as a password verifier",
			Reason:              "the stored digest is what a later login is checked against, and an algorithm broken against collision lets a value that is not the password satisfy that check",
			Rationale:           "a digest from a broken algorithm is written into the field a password is verified against",
		},
		{
			// PATH decides where the next program comes from. A caller who can prepend to
			// it chooses which binary every later exec actually runs, and nothing about
			// the exec looks wrong.
			ID: "untrusted-into-search-path", Class: "untrusted-input",
			Into: []string{"env", "environ"}, Path: []string{"PATH", "NODE_PATH", "PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH"},
			CWE:       "CWE-427",
			Finding:   "Caller's data written into an executable search path",
			Reason:    "the search path decides which binary the next exec actually runs, so a caller who can write to it chooses the program without touching the call that runs it",
			Rationale: "the value written into the search path came from the request",
		},
		{
			// The environment is read by everything the process later starts, and by
			// libraries that look for their own configuration in it. The search-path keys
			// are excluded because the rule above already claims them, at a granularity
			// that says something sharper about what goes wrong.
			ID: "untrusted-into-environment", Class: "untrusted-input",
			Into:      []string{"env", "environ"},
			NotPath:   []string{"PATH", "NODE_PATH", "PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH"},
			CWE:       "CWE-15",
			Finding:   "Caller's data written into the environment",
			Reason:    "the environment is inherited by every process this one starts and is where libraries look for their own configuration, so a caller who can write to it reconfigures things that never read the request",
			Rationale: "the value written into the environment came from the request",
		},
	}
}

// --- a store as a place values come from ----------------------------------

// StoreAccess is one end of a PERSISTENT STORE: a call that puts a value into one, or a
// call that takes a value back out.
//
// The engine had no notion of a store at all, and the same missing fact was producing two
// opposite defects. A read was assumed to return whatever it was HANDED, so
// `cache.get(id)` answered with the caller's identifier rather than with the cached row,
// and taint flowed from the key a lookup was given into the value it returned -- three of
// one repository's false positives rested on that single step, one of them a 49-hop path
// onto genuinely raw SQL where the SQL was real and the taint was not. From the other
// side, a value a request WROTE to a database arrived at a later request looking clean,
// because taint is intra-request and nothing carried the fact across.
//
// Both are the same sentence: a read answers with what was WRITTEN, and what was written
// is a separate question with a separate provenance. Saying that once fixes the
// over-approximation and makes the under-approximation expressible.
//
// The proof that this is one fact rather than two is a finding that disappeared on its
// own: misskey's `OAuth2ProviderService.ts:726` went quiet the moment
// `grantCodeCache.get(code)` resolved to a real function, because a resolved getter is
// visibly returning the stored value instead of its argument. Where the callee resolves
// the engine was already right; where it did not, it assumed the worst.
type StoreAccess struct {
	ID string
	// Medium is what KIND of store this is -- "orm", "key-value", "session",
	// "browser-storage". It is not the store's identity: two caches are two stores of
	// one medium, and connecting a write to a read requires the identity as well.
	Medium string
	// Direction is "read" or "write".
	Direction string

	// Method matches the call's method name, which is how a store is reached in every
	// library either frontend has seen: the receiver is the store and the method is the
	// verb.
	Method []string
	// Symbol matches the whole rendered callee, for the few reads written as a free
	// function rather than as a method. Django's `get_object_or_404(Model, pk=...)` is
	// one, and there is no receiver in it to recognise.
	Symbol []string

	// MethodAlone says the method NAME is evidence enough, without anything being known
	// about the receiver.
	//
	// True only where the name belongs to one library's data-access API and to nothing
	// else a program is likely to write: `findOneBy`, `findUnique`, `getItem`. It is
	// false for `get` and `find`, which are the two most overloaded method names in both
	// languages -- `fastify.get` registers a route, `axios.get` makes a request,
	// `Array.prototype.find` searches a list the program built a line earlier, and
	// treating any of those as a store would be worse than the defect this replaces.
	MethodAlone bool

	// ReceiverType names the types whose values ARE stores, as the frontend's checker
	// reports them. This is the seam doing its job: whether `x.get(id)` reaches a Map or
	// a route table is a question about the LANGUAGE, and only the frontend can answer
	// it (ADR-001).
	ReceiverType []string
	// ReceiverWord matches a WORD in how the receiver was SPELLED, for the ordinary case
	// where the frontend could not type it -- 55% of method receivers in the largest
	// repository measured. `this.usersRepository.findOneBy` and `this.cache.get` say what
	// they are in the name; `fastify.get` and `res.headers.get` do not.
	ReceiverWord []string
	// SymbolContains matches a marker anywhere in the rendered callee. Django spells its
	// manager into every query -- `Check.objects.get`, `Channel.objects.filter` -- and
	// that marker is both the evidence and the place the model's name is read from.
	SymbolContains []string

	// NamedBefore says the store's own NAME is the symbol segment immediately before the
	// text it holds, so that a write and a read can be required to name the SAME table
	// rather than merely to be a write and a read.
	//
	// Second-order taint is the most noise-prone thing in static analysis: connect every
	// write to every read and everything is tainted by everything. A named store is the
	// whole of what keeps it from being that.
	NamedBefore string

	// ValueArg is the argument holding the value being written, for a write. A read has
	// no value argument: everything a read is handed is criteria.
	ValueArg int
}

// storeCriteriaOptions are the option groups that say WHICH ROW rather than what is in
// it. A key under one of these is a filter the caller was matched against, not a column
// the caller filled in.
var storeCriteriaOptions = []string{
	"where", "select", "include", "orderby", "skip", "take", "cursor",
	"distinct", "by", "omit", "having", "filter", "criteria",
}

// storeWrapperOptions are the group names libraries wrap the written columns in. The
// group is not itself a column, and where the frontend could see only the group -- a
// shorthand `create({ data })` whose fields were assembled elsewhere -- the honest answer
// is that this write names no field at all.
var storeWrapperOptions = []string{
	"data", "values", "set", "attributes", "fields", "doc", "defaults", "payload",
}

// WrittenFields reads the COLUMN NAMES a write names, out of the option keys the
// frontend recorded at the call.
//
// This is what makes a store connection narrow enough to be worth having. "Some route
// writes this table" connects a write of `name` to a read of `id`, and the primary key
// an auto-increment column produced is not something a caller chose -- the first version
// of this rule said it was, and the one finding it produced across ten repositories was
// a file path built out of exactly that. Naming the column on both sides is the
// difference between a claim about a table and a claim about a value.
//
// A key written with a LITERAL is excluded, which is the same judgement every other
// literal-reading rule in this model makes: `{ status: "active" }` is the program
// deciding, and no caller reaches the field it decided.
func (s StoreAccess) WrittenFields(literals map[int]string) []string {
	type entry struct{ path, value string }
	var entries []entry
	group := map[string]bool{}
	for idx, text := range literals {
		// Negative indices are where both frontends keep option keys: an object
		// literal's properties in TypeScript, keyword arguments in Python.
		if idx >= 0 {
			continue
		}
		eq := strings.LastIndex(text, "=")
		if eq < 0 {
			continue
		}
		entries = append(entries, entry{text[:eq], text[eq+1:]})
		if i := strings.Index(text[:eq], "."); i > 0 {
			group[strings.ToLower(text[:i])] = true
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		if e.value != ir.UnknownLiteral {
			continue
		}
		head, leaf := strings.ToLower(e.path), e.path
		nested := false
		if i := strings.Index(e.path, "."); i > 0 {
			head, leaf, nested = strings.ToLower(e.path[:i]), e.path[i+1:], true
			if j := strings.LastIndex(leaf, "."); j >= 0 {
				leaf = leaf[j+1:]
			}
		}
		if namedIn(storeCriteriaOptions, head) {
			continue
		}
		if !nested && (group[head] || namedIn(storeWrapperOptions, head)) {
			continue
		}
		leaf = NormalizeFieldName(leaf)
		if leaf == "" || seen[leaf] {
			continue
		}
		seen[leaf] = true
		out = append(out, leaf)
	}
	return out
}

// WrittenGroups reads the same option keys WrittenFields does, keeping the group each
// column was written under instead of flattening them together.
//
// The flattening is right for the question WrittenFields answers -- which columns does
// this call write, so a write and a read can be required to name the same one -- and
// wrong for a call that says two different things about two different situations. An
// upsert's `create` and `update` are not one field list: the whole content of the
// judgement here is that a column appears in one of them and not the other, and a
// flattened list has already thrown that away.
//
// Literal-valued keys are excluded on the same terms as WrittenFields: `{ status:
// "active" }` is the program deciding, and no caller reaches the field it decided.
func (s StoreAccess) WrittenGroups(literals map[int]string) map[string][]string {
	out := map[string][]string{}
	seen := map[string]bool{}
	for idx, text := range literals {
		// Negative indices are where both frontends keep option keys.
		if idx >= 0 {
			continue
		}
		eq := strings.LastIndex(text, "=")
		if eq < 0 || text[eq+1:] != ir.UnknownLiteral {
			continue
		}
		path := text[:eq]
		i := strings.Index(path, ".")
		if i <= 0 {
			continue
		}
		group, leaf := strings.ToLower(path[:i]), path[i+1:]
		// A column nested deeper than its group is a nested write -- Prisma's related
		// `create` inside a `create` -- and belongs to whatever that inner group is
		// rather than to this one.
		if strings.Contains(leaf, ".") {
			continue
		}
		if namedIn(storeCriteriaOptions, group) {
			continue
		}
		leaf = NormalizeFieldName(leaf)
		if leaf == "" || seen[group+"."+leaf] {
			continue
		}
		seen[group+"."+leaf] = true
		out[group] = append(out[group], leaf)
	}
	for _, fields := range out {
		sort.Strings(fields)
	}
	return out
}

// NormalizeFieldName folds the spellings one column is written in: a schema declares
// `created_at` and an ORM exposes `createdAt`.
func NormalizeFieldName(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", ""))
}

// StoreReadAt returns the store rule this call reads through, when it reads through one.
//
// Receiver facts are passed in rather than looked up, the same way ChannelsMatching takes
// them: the engine is the only side that knows what a receiver resolved to.
func (m Model) StoreReadAt(symbol, method, receiverType string) (StoreAccess, bool) {
	return m.storeAccessAt("read", symbol, method, receiverType)
}

// StoreWriteAt returns the store rule this call writes through, when it writes through one.
func (m Model) StoreWriteAt(symbol, method, receiverType string) (StoreAccess, bool) {
	return m.storeAccessAt("write", symbol, method, receiverType)
}

func (m Model) storeAccessAt(direction, symbol, method, receiverType string) (StoreAccess, bool) {
	for _, s := range m.Persistence {
		if s.Direction != direction {
			continue
		}
		if s.Matches(symbol, method, receiverType) {
			return s, true
		}
	}
	return StoreAccess{}, false
}

// Matches reports whether this call reaches the store this rule describes.
func (s StoreAccess) Matches(symbol, method, receiverType string) bool {
	if namedIn(s.Symbol, symbol) {
		return true
	}
	if method == "" || !namedIn(s.Method, method) {
		return false
	}
	if s.MethodAlone {
		return true
	}
	for _, t := range s.ReceiverType {
		if receiverType == t {
			return true
		}
	}
	for _, marker := range s.SymbolContains {
		if strings.Contains(symbol, marker) {
			return true
		}
	}
	if word := receiverSpelling(symbol, method); word != "" {
		for _, w := range s.ReceiverWord {
			if strings.Contains(word, w) {
				return true
			}
		}
	}
	return false
}

// StoreName reads the store's own identity out of the callee spelling, or returns empty
// when the spelling does not carry one.
//
// `this.usersRepository.findOneBy` names the users table, `prisma.client.website.create`
// names the website model, and `Check.objects.get` names Check. A `Map` reached through a
// receiver the frontend could only type names nothing, and a rule that needs the identity
// declines rather than connecting two stores that merely share a medium.
func (s StoreAccess) StoreName(symbol, method string) string {
	if s.NamedBefore == "" {
		return ""
	}
	rest := symbol
	if strings.HasSuffix(rest, "."+method) {
		rest = rest[:len(rest)-len(method)-1]
	}
	if s.NamedBefore != "." {
		i := strings.LastIndex(rest, s.NamedBefore)
		if i < 0 {
			return ""
		}
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "."); i >= 0 {
		rest = rest[i+1:]
	}
	return normalizeStoreName(rest)
}

// normalizeStoreName folds the spellings one table is written in. TypeORM injects
// `usersRepository`, Prisma exposes `user`, and Django declares `User`: all three name one
// table, and a connection that required them to match character for character would
// connect nothing.
func normalizeStoreName(name string) string {
	n := strings.ToLower(name)
	n = strings.TrimPrefix(n, "this.")
	for _, suffix := range []string{"repository", "repo", "model", "table", "s"} {
		if len(n) > len(suffix) && strings.HasSuffix(n, suffix) {
			n = n[:len(n)-len(suffix)]
			break
		}
	}
	return n
}

// namedIn reports membership of a rule's name list.
func namedIn(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// receiverSpelling returns the last segment of how the receiver was written, lowercased.
func receiverSpelling(symbol, method string) string {
	rest := symbol
	if strings.HasSuffix(rest, "."+method) {
		rest = rest[:len(rest)-len(method)-1]
	}
	if rest == "" || rest == symbol {
		return ""
	}
	if i := strings.LastIndex(rest, "."); i >= 0 {
		rest = rest[i+1:]
	}
	return strings.ToLower(rest)
}

func builtinPersistence() []StoreAccess {
	return []StoreAccess{
		// --- reads: a lookup answers with what was stored ---------------------
		{
			// The data-access names that belong to one library's API and to nothing a
			// program is likely to write for itself. Each of these is safe on its name
			// alone, which matters because the receiver is untyped at more than half the
			// method calls in a large TypeScript repository and at all of them in Python.
			ID: "orm-read-by-name", Medium: "orm", Direction: "read",
			Method: []string{
				"findOne", "findOneBy", "findOneOrFail", "findOneByOrFail", "findBy",
				"findAndCount", "findAndCountBy", "findOneById",
				"findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "findMany",
				"findAll", "findByPk", "findById",
				"getOne", "getMany", "getRawOne", "getRawMany", "getOneOrFail",
			},
			MethodAlone: true,
			NamedBefore: ".",
		},
		{
			// Django writes its manager into every query, so the marker that says this is
			// a table read is the same segment that says WHICH table.
			ID: "orm-read-django", Medium: "orm", Direction: "read",
			Method: []string{
				"get", "filter", "exclude", "first", "last", "latest", "earliest", "all",
				"values", "values_list", "in_bulk", "only", "defer", "order_by", "distinct",
				"select_related", "prefetch_related", "annotate", "aget", "afirst",
			},
			SymbolContains: []string{".objects."},
			NamedBefore:    ".objects.",
		},
		{
			// The two shortcuts that ARE a query with a rejection attached. There is no
			// receiver in either to recognise, so they are named whole.
			ID: "orm-read-shortcut", Medium: "orm", Direction: "read",
			Symbol: []string{
				"django.shortcuts.get_object_or_404", "django.shortcuts.get_list_or_404",
				"get_object_or_404", "get_list_or_404",
			},
		},
		{
			// A container reached by key. `get` is the most overloaded method name in
			// either language -- it registers a route, makes an HTTP request, reads a
			// header and searches a form -- so it is never matched on the name: either
			// the frontend typed the receiver as a container, or the receiver says in its
			// own spelling what it is.
			ID: "key-value-read", Medium: "key-value", Direction: "read",
			Method: []string{"get", "peek", "mget", "hget", "hgetall", "fetch", "lookup", "retrieve"},
			ReceiverType: []string{
				"Map", "WeakMap", "Cache", "Redis", "IORedis",
				"MemoryKVCache", "MemorySingleCache", "QuantumKVCache",
				"RedisKVCache", "RedisSingleCache",
			},
			ReceiverWord: []string{"cache", "store", "registry", "redis", "memo", "keyv", "lru"},
			NamedBefore:  ".",
		},
		{
			// Browser storage. `getItem` is unambiguous and `localStorage` is typed
			// `Storage` by the checker, so both halves agree.
			ID: "browser-storage-read", Medium: "browser-storage", Direction: "read",
			Method: []string{"getItem", "key"}, ReceiverType: []string{"Storage"},
			MethodAlone: true, NamedBefore: ".",
		},
		{
			// A session read, spelled through the request that carries it. Deliberately
			// NOT matched on the word `session` alone: `requests.Session().get(url)` is an
			// outbound HTTP call written with the same two words, and treating it as a
			// store would silence server-side request forgery.
			ID: "session-read", Medium: "session", Direction: "read",
			Method: []string{"get", "pop", "setdefault"},
			SymbolContains: []string{
				"request.session.", "req.session.", "ctx.session.", "context.session.",
			},
			NamedBefore: ".",
		},

		// --- writes: where a value ENTERS a store -----------------------------
		{
			ID: "orm-write-by-name", Medium: "orm", Direction: "write",
			Method: []string{
				"create", "createMany", "insert", "upsert", "bulkCreate",
				"insertOne", "insertMany", "updateOne", "updateMany", "replaceOne",
				"findOneAndUpdate", "findOneAndReplace",
			},
			MethodAlone: true, NamedBefore: ".", ValueArg: -1,
		},
		{
			ID: "orm-write-django", Medium: "orm", Direction: "write",
			Method:         []string{"create", "bulk_create", "get_or_create", "update_or_create", "update", "acreate"},
			SymbolContains: []string{".objects."},
			NamedBefore:    ".objects.", ValueArg: -1,
		},
		{
			ID: "browser-storage-write", Medium: "browser-storage", Direction: "write",
			Method: []string{"setItem"}, ReceiverType: []string{"Storage"},
			MethodAlone: true, NamedBefore: ".", ValueArg: 1,
		},
		{
			ID: "key-value-write", Medium: "key-value", Direction: "write",
			Method: []string{"set", "put", "hset", "mset", "add"},
			ReceiverType: []string{
				"Map", "WeakMap", "Cache", "Redis", "IORedis",
				"MemoryKVCache", "MemorySingleCache", "QuantumKVCache",
				"RedisKVCache", "RedisSingleCache",
			},
			ReceiverWord: []string{"cache", "store", "registry", "redis", "memo", "keyv", "lru"},
			NamedBefore:  ".", ValueArg: 1,
		},
		{
			ID: "session-write", Medium: "session", Direction: "write",
			Method: []string{"set", "update"},
			SymbolContains: []string{
				"request.session.", "req.session.", "ctx.session.", "context.session.",
			},
			NamedBefore: ".", ValueArg: 1,
		},
	}
}
