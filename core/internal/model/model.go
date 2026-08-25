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
	// MatchGlobalProperty: a property access on a framework-bound global, e.g.
	// Flask's `request`. Added because a request object is not always a handler
	// parameter — the judgement is identical, the plumbing is not.
	MatchGlobalProperty = "global-property"
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

	// MatchCallResult
	Symbol string

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

// CallbackRule propagates a class from a method's receiver into a function passed as
// an argument to it. This is what carries data across the callback and promise
// boundaries that most of Node is built out of.
type CallbackRule struct {
	Method        string
	CallbackArg   int
	CallbackParam int
	Note          string
}

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
	return missing
}

// --- model ----------------------------------------------------------------

type Model struct {
	Classifications []Classification
	Channels        []Channel
	CallShapes      []CallShape
	Decisions       []DecisionRule
	Stores          []StoreRule
	Policies        []Policy
	Sanitizers      []SanitizerRule
	Callbacks       []CallbackRule
	Controls        []ControlRule
	TaintFlowReq    Requirements
	SurfaceReq      Requirements
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

// CallbackFor returns the higher-order propagation rule for a method name, if any.
func (m Model) CallbackFor(method string) (CallbackRule, bool) {
	for _, c := range m.Callbacks {
		if c.Method == method {
			return c, true
		}
	}
	return CallbackRule{}, false
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
	segment = strings.ToLower(segment)

	best, bestLen := "", 0
	for _, c := range m.Controls {
		rule := strings.ToLower(c.Name)
		if len(rule) > bestLen && strings.Contains(segment, rule) {
			best, bestLen = c.Kind, len(rule)
		}
	}
	return best
}

// Builtin returns the shipped model.
// Field names that ARE a claim of authority rather than merely mentioning one. Compared
// exactly, ignoring case and separators: containment reads `adminEmail` as a privilege,
// and a setup form is not a security decision.
// Facts about a person that cannot be reissued. Deliberately specific: `passport` alone
// is the authentication library in two of the three places these names appear across the
// clean corpus, and a list that matched it would report a login flow as an identity leak.
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

func Builtin() Model {
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
					{
						// Frameworks that inject request data straight into a
						// handler parameter (NestJS @Param/@Body/@Query).
						Match:     MatchValueKind,
						ValueKind: "untrusted-param",
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
				CWE:       "CWE-502",
				Rationale: "pickle reconstructs arbitrary objects by calling their constructors",
			},
			{
				// yaml.load without an explicit safe loader constructs Python objects.
				// yaml.safe_load is a different symbol and is deliberately absent.
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "yaml.load", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-502",
				Rationale: "yaml.load constructs Python objects unless given a safe loader",
			},
			{
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "yaml.unsafe_load", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-502",
				Rationale: "the name is the documentation: this loader constructs whatever the document names",
			},
			{
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "yaml.full_load", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-502",
				Rationale: "the full loader constructs arbitrary Python objects",
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
				CWE:       "CWE-502",
				Rationale: "jsonpickle reconstructs objects by importing the classes the document names",
			},
			{
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "dill.loads", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-502",
				Rationale: "dill extends pickle and reconstructs arbitrary objects the same way",
			},
			{
				ID: "object-deserializer", Visibility: "internal", Context: "deserialize",
				Symbol: "shelve.open", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-502",
				Rationale: "a shelf is a pickle file, so opening one the caller named unpickles what it holds",
			},

			// Where an outbound request GOES, as opposed to what it carries. The same
			// axios.post is two different destinations depending on which argument is
			// being asked about: argument 1 is data leaving the trust boundary, and
			// argument 0 is the caller choosing which machine the application talks to
			// from inside the network. Different arguments, different judgements, one
			// call.
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "axios.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "axios.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "axios.put", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "axios.delete", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "axios.request", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "node-fetch.default", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "http.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "http.request", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "https.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "https.request", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "got.default", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "superagent.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "requests.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "requests.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "requests.put", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "requests.delete", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "requests.head", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "urllib.request.urlopen", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "httpx.get", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "httpx.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
			},
			{
				ID: "outbound-destination", Visibility: "internal", Context: "url",
				Symbol: "fetch", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                "CWE-918",
				RequiresWholeValue: true,
				Rationale:          "the first argument is the address this request is sent to",
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
				CWE:       "CWE-598",
				Rationale: "the first argument is the URL this request is sent to",
			},
			{
				ID: "outbound-url", Visibility: "internal", Context: "url-query",
				Symbol: "requests.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-598",
				Rationale: "the first argument is the URL this request is sent to",
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
				Symbol: "requests.post", ReceiverIsEntryParam: -1, ArgIndex: []int{1, -1},
				Qualifiers: []ArgCondition{{ArgIndex: 0, AnyOf: []string{"http://"}, Substring: true}},
				CWE:        "CWE-319",
				Rationale:  "the destination is written into the call as a plaintext URL",
			},
			{
				ID: "plaintext-outbound-body", Visibility: "thirdparty", Context: "plaintext-url",
				Symbol: "requests.put", ReceiverIsEntryParam: -1, ArgIndex: []int{1, -1},
				Qualifiers: []ArgCondition{{ArgIndex: 0, AnyOf: []string{"http://"}, Substring: true}},
				CWE:        "CWE-319",
				Rationale:  "the destination is written into the call as a plaintext URL",
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
				RequiresArgs: 1,
				CWE:          "CWE-134",
				Rationale:    "format() is called ON caller-supplied text, so the caller wrote the format",
			},
			{
				ID: "format-string", Visibility: "internal", Context: "format",
				Method: "format_map", ReceiverIsEntryParam: -1, RequiresUntrustedReceiver: true,
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
				CWE:       "CWE-434",
				Rationale: "writes an uploaded file to a destination the caller named",
			},
			{
				// express-fileupload moves the temporary file into place.
				ID: "stored-upload-destination", Visibility: "internal", Context: "upload-type",
				Method: "mv", ReceiverIsEntryParam: -1, RequiresUntrustedReceiver: true, ArgIndex: []int{0},
				CWE:       "CWE-434",
				Rationale: "moves an uploaded file to a destination the caller named",
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
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this opens",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "os.remove", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file this deletes",
			},
			{
				ID: "filesystem-path", Visibility: "internal", Context: "path",
				Symbol: "flask.send_file", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-22",
				Rationale: "the first argument names the file sent to the caller",
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
				Rationale:                "modifies a single record by the identifier it is given",
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
				Rationale:           "the first argument is executed as SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "execute", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				Rationale:           "the first argument is executed as SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "executemany", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				Rationale:           "the first argument is executed as SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "raw", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				Rationale:           "raw() hands its argument to the database as SQL",
			},
			{
				// Named Unsafe by its own authors, for this reason.
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "$queryRawUnsafe", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
				Rationale:           "$queryRawUnsafe() interpolates its argument into SQL",
			},
			{
				ID: "sql-query", Visibility: "internal", Context: "sql",
				Method: "$executeRawUnsafe", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:                 "CWE-89",
				RequiresComposition: true,
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
				Method: "aggregate", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				Qualifiers: []ArgCondition{{Keyword: "$where"}},
				CWE:        "CWE-95",
				Rationale:  "$where is a JavaScript expression MongoDB evaluates on the server",
			},
			{
				ID: "code-interpreter", Visibility: "internal", Context: "code",
				Method: "distinct", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
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
				CWE: "CWE-78", RequiresComposition: true,
				Rationale: "a composed string passed here is run by the shell",
			},
			{
				ID: "shell-command", Visibility: "internal", Context: "shell",
				Symbol: "subprocess.call", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE: "CWE-78", RequiresComposition: true,
				Rationale: "a composed string passed here is run by the shell",
			},
			{
				ID: "shell-command", Visibility: "internal", Context: "shell",
				Symbol: "subprocess.check_output", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE: "CWE-78", RequiresComposition: true,
				Rationale: "a composed string passed here is run by the shell",
			},
			{
				ID: "shell-command", Visibility: "internal", Context: "shell",
				Symbol: "subprocess.Popen", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE: "CWE-78", RequiresComposition: true,
				Rationale: "a composed string passed here is run by the shell",
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
				Symbol: "requests.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, -1},
				Qualifiers: []ArgCondition{{ArgIndex: 0, Substring: true, NoneOf: []string{"http://"}}},
				Rationale:  "leaves this trust boundary for a system we do not control",
			},
			{
				ID: "outbound-http", Visibility: "thirdparty",
				Symbol: "requests.put", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, -1},
				Qualifiers: []ArgCondition{{ArgIndex: 0, Substring: true, NoneOf: []string{"http://"}}},
				Rationale:  "leaves this trust boundary for a system we do not control",
			},
			{
				ID: "outbound-http", Visibility: "thirdparty",
				Symbol: "requests.patch", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, -1},
				Qualifiers: []ArgCondition{{ArgIndex: 0, Substring: true, NoneOf: []string{"http://"}}},
				Rationale:  "leaves this trust boundary for a system we do not control",
			},
			{
				ID: "outbound-http", Visibility: "thirdparty",
				Symbol: "httpx.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, -1},
				Qualifiers: []ArgCondition{{ArgIndex: 0, Substring: true, NoneOf: []string{"http://"}}},
				Rationale:  "leaves this trust boundary for a system we do not control",
			},
		},

		// WHAT IS FORBIDDEN. Judgements about class-and-channel pairings. Each covers
		// every instance of the pairing, including channels added later.
		CallShapes: builtinCallShapes(),
		Decisions:  builtinDecisions(),
		Stores:     builtinStores(),

		Policies: []Policy{
			{
				ID:            "untrusted-to-interpreter",
				Class:         "untrusted-input",
				DeniedContext: []string{"shell", "exec-path", "sql", "html", "code", "template", "ldap", "xpath"},
				Reason:        "a caller must not be able to choose what an interpreter executes",
				Finding:       "Untrusted input reaches an interpreter",
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
				DeniedContext:       []string{"http-response", "html"},
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
				ID:               "internal-detail-outward",
				Class:            "internal-error",
				DeniedVisibility: []string{"public", "thirdparty"},
				Reason:           "internal failure detail describes the system to people outside it",
				Finding:          "Sensitive information exposure",
				CWE:              "CWE-209",
			},
		},

		Sanitizers: []SanitizerRule{
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
				Note:     "produces a number, which cannot carry syntax",
			},
			{
				Symbol:   "parseFloat",
				Contexts: []string{AnyContext},
				Note:     "produces a number, which cannot carry syntax",
			},
			{
				Symbol:   "Number",
				Contexts: []string{AnyContext},
				Note:     "produces a number, which cannot carry syntax",
			},
			{
				Symbol:   "builtins.int",
				Contexts: []string{AnyContext},
				Note:     "produces a number, which cannot carry syntax",
			},
			{
				Symbol:   "builtins.float",
				Contexts: []string{AnyContext},
				Note:     "produces a number, which cannot carry syntax",
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
				Method:      "digest",
				AfterSymbol: []string{"createHash", "createHmac"},
				Contexts:    []string{AnyContext},
				Note:        "a digest is not what was digested, and a hex digest cannot carry syntax",
			},
			{
				Method:      "hexdigest",
				AfterSymbol: []string{"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "new"},
				Contexts:    []string{AnyContext},
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
				Contexts: []string{"html"},
				Note:     "escapes the five characters that make markup",
			},
			{
				// The same package reached through a default import. A module's identity
				// is not the name a file happened to bind it to.
				Symbol:   "escape-html.default",
				Contexts: []string{"html"},
				Note:     "escapes the five characters that make markup",
			},
			{
				Symbol:   "he.escape",
				Contexts: []string{"html"},
				Note:     "HTML-encodes its input",
			},
			{
				Symbol:   "he.encode",
				Contexts: []string{"html"},
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
				Contexts: []string{"html"},
				Note:     "escapes the five characters that make markup and returns Markup",
			},
			{
				Symbol:   "flask.escape",
				Contexts: []string{"html"},
				Note:     "escapes the five characters that make markup and returns Markup",
			},
			{
				Symbol:   "html.escape",
				Contexts: []string{"html"},
				Note:     "HTML-escapes its input",
			},
			{
				Symbol:   "cgi.escape",
				Contexts: []string{"html"},
				Note:     "HTML-escapes its input",
			},
			{
				Symbol:   "bleach.clean",
				Contexts: []string{"html"},
				Note:     "removes scripting constructs from markup",
			},

			{
				Symbol:   "shell-quote.quote",
				Contexts: []string{"shell"},
				Note:     "quotes arguments for shell interpretation",
			},
			{
				Symbol:   "encodeURIComponent",
				Contexts: []string{"url"},
				Note:     "percent-encodes for a URL context only; it neutralizes nothing for any other context",
			},
		},

		Callbacks: []CallbackRule{
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
		},
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
		return false
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

func builtinCallShapes() []CallShape {
	weakHash := []string{"md5", "sha1", "md4", "md2", "ripemd", "sha"}

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
			ID: "unverified-signature", AnyCall: true, Keyword: "verify",
			Disallowed:   []string{"false"},
			Qualifiers:   []ArgCondition{{Keyword: "algorithms"}},
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
			// An ABSENCE rule, so it only speaks where the option keys were actually
			// enumerated. Options built in another function are unknowable and are passed
			// over in silence.
			ID: "unexpiring-token", Symbol: "jsonwebtoken.sign",
			RequiredKeyword: "expiresIn", RequiredAnyOf: []string{"expiresIn", "exp"},
			OptionsArg: 2, OptionsMustBeWritten: true, AlsoEnumerated: []int{0},
			CWE:       "CWE-613",
			Finding:   "Signed token issued with no expiry",
			Reason:    "a signed token carries no revocation of its own, so unless the server keeps state to check it against, the only thing that ends one is its expiry",
			Rationale: "the options argument to sign() enumerates its keys and expiresIn is not among them",
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
			ID: "opener-reachable", Symbol: "window.open", MissingArg: atLeast(2),
			Qualifiers: []ArgCondition{{ArgIndex: 1, Substring: true, AnyOf: []string{"_blank", "blank"}}},
			CWE:        "CWE-1022",
			Finding:    "A new window left holding a reference back to this one",
			Reason:     "the opened page can navigate the page that opened it, which is how a link to somewhere else replaces the page behind it with a copy that asks for a password",
			Rationale:  "the third argument is where noopener would be, and the call has no third argument",
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
			ID: "unverified-download", Symbol: "subprocess.getoutput", ArgIndex: 0, Always: true,
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
			ID: "predictable-iv", Symbol: "crypto.createCipheriv", ArgIndex: 2, AnyLiteral: true,
			Qualifiers: []ArgCondition{{ArgIndex: 2, NoneOf: []string{"null", "undefined"}}},
			CWE:        "CWE-329",
			Finding:    "Initialisation vector written into the source",
			Reason:     "an IV must be unpredictable and must never repeat, and one written down is both predictable and reused on every message",
			Rationale:  "the third argument to createCipheriv() is the IV",
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

		{
			ID: "weak-hash", Symbol: "crypto.createHash", ArgIndex: 0, Disallowed: weakHash,
			DependsOnUse: "whether a broken digest matters depends on what it is used for, which this call does not carry: the same call builds a cache key, a filename, and a Gravatar URL",
			CWE:          "CWE-328",
			Finding:      "Weak hash algorithm",
			Reason:       "the algorithm is broken against collision, so a digest does not establish what it is used to establish",
			Rationale:    "createHash() is given the algorithm by name",
		},
		{
			ID: "weak-hash", Symbol: "crypto.createHmac", ArgIndex: 0, Disallowed: []string{"md5", "md4", "md2"},
			DependsOnUse: "whether a broken digest matters depends on what it is used for, which this call does not carry",
			CWE:          "CWE-328",
			Finding:      "Weak hash algorithm",
			Reason:       "the algorithm is broken against collision, so a digest does not establish what it is used to establish",
			// HMAC-SHA1 is not currently considered broken, so it is deliberately absent
			// from this list while being present for a bare hash.
			Rationale: "createHmac() is given the algorithm by name",
		},
		{
			ID: "weak-hash", Symbol: "hashlib.new", ArgIndex: 0, Disallowed: weakHash,
			DependsOnUse: "whether a broken digest matters depends on what it is used for, which this call does not carry: the same call builds a cache key, a filename, and a Gravatar URL",
			CWE:          "CWE-328",
			Finding:      "Weak hash algorithm",
			Reason:       "the algorithm is broken against collision, so a digest does not establish what it is used to establish",
			Rationale:    "hashlib.new() is given the algorithm by name",
		},
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
			Disallowed: []string{"debug=true"},
			CWE:        "CWE-489",
			Finding:    "Debug mode enabled",
			Reason:     "the debug server exposes an interactive console that executes code sent to it, so this is remote code execution wherever it is reachable",
			Rationale:  "run() is passed debug=True",
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

	// RequiresUnprojected forbids the judgement for a value read OUT of a structure the
	// classification reached.
	//
	// A credential handed to a function and a field read back off what it returned are
	// not the same value: `session.tenantId !== current` compares a tenant id, and that a
	// token was involved in producing the session does not make a tenant id a secret.
	// Four findings in one production repository were exactly that.
	RequiresUnprojected bool

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
			ID: "credential-compared-in-variable-time", Class: "caller-credential",
			Ops:                 []string{"==", "===", "!=", "!==", "Eq", "NotEq"},
			OtherNotLiteral:     true,
			OtherNotSameClass:   true,
			RequiresUnprojected: true,
			CWE:                 "CWE-208",
			Finding:             "Secret compared in variable time",
			Reason:              "the comparison stops at the first byte that differs, so how long it takes says how much of the guess was right, and enough guesses recover the whole value",
			Rationale:           "a value the caller sent as a credential is compared with the language's equality operator",
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
	// NotPath excludes keys another rule already claims, so two rules can describe the
	// same destination at different granularities without reporting one line twice.
	NotPath []string
	// RequiresUnprojected forbids the judgement for a value read OUT of something the
	// classification reached. `accountability.admin = userGlobalAccess.admin` writes a
	// field of what a server-side lookup returned, and that the lookup was once handed a
	// request does not make its answer the caller's.
	RequiresUnprojected bool

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
	// NotInto is the same exclusion on the DESTINATION rather than the key.
	//
	// `req.session.role = req.body.role` is a privilege set from the request AND a
	// caller's claim laundered across a trust boundary. Both readings are true and the
	// line is one line, so the narrower rule keeps it and the broader one stands aside.
	NotInto []string

	CWE       string
	Finding   string
	Reason    string
	Rationale string
}

func builtinStores() []StoreRule {
	return []StoreRule{
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
