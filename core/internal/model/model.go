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
}

// arg is a pointer to an argument index, for the optional condition above.
func arg(i int) *int { return &i }

// atLeast is a pointer to a threshold, for a shape that matches values below it.
func atLeast(i int) *int { return &i }

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
		if s.Symbol == symbol {
			return s, true
		}
	}
	return SanitizerRule{}, false
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
				ID: "log", Visibility: "operator", Symbol: "console.log", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				CWE:       "CWE-532",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "console.info", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				CWE:       "CWE-532",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "console.warn", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				CWE:       "CWE-532",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "console.error", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				CWE:       "CWE-532",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "console.debug", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				CWE:       "CWE-532",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "logging.info", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				CWE:       "CWE-532",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "logging.warning", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				CWE:       "CWE-532",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "logging.error", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				CWE:       "CWE-532",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "logging.debug", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				CWE:       "CWE-532",
				Rationale: "written to a log",
			},
			{
				ID: "log", Visibility: "operator", Symbol: "logging.exception", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1, 2},
				CWE:       "CWE-532",
				Rationale: "written to a log",
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
				CWE:       "CWE-611",
				Rationale: "lxml's default parser resolves entities",
			},
			{
				ID: "xml-parser", Visibility: "internal", Context: "xml",
				Symbol: "lxml.etree.XML", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-611",
				Rationale: "lxml's default parser resolves entities",
			},
			{
				ID: "xml-parser", Visibility: "internal", Context: "xml",
				Symbol: "lxml.etree.parse", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
				CWE:       "CWE-611",
				Rationale: "lxml's default parser resolves entities",
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
				Symbol: "fs/promises.readFileSync", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
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
				Symbol: "fs/promises.writeFileSync", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
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
				Symbol: "fs/promises.appendFileSync", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
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
				Symbol: "fs/promises.createReadStream", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
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
				Symbol: "fs/promises.createWriteStream", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
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
				Symbol: "fs/promises.unlinkSync", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
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
				Symbol: "fs/promises.rmSync", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
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
				Symbol: "fs/promises.readdirSync", ReceiverIsEntryParam: -1, ArgIndex: []int{0},
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
			{
				// Added as a DESCRIPTION of a channel, not as a rule for a defect.
				// Every policy that denies a class reaching "thirdparty" now covers
				// outbound HTTP without being touched.
				ID: "outbound-http", Visibility: "thirdparty",
				Symbol: "axios.post", ReceiverIsEntryParam: -1, ArgIndex: []int{0, 1},
				Rationale: "leaves this trust boundary for a system we do not control",
			},
		},

		// WHAT IS FORBIDDEN. Judgements about class-and-channel pairings. Each covers
		// every instance of the pairing, including channels added later.
		CallShapes: builtinCallShapes(),

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
			if key, _, cut := strings.Cut(l, "="); cut && strings.ToLower(key) == want {
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
			if cut && strings.ToLower(key) == want {
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

	// AnyLiteral matches when the argument was written as a literal at all, whatever it
	// says. For an argument that is supposed to hold a secret, being written down IS the
	// defect and its contents are beside the point -- and the same test is what makes it
	// precise, because a secret read from the environment or a vault is not a literal
	// and never matches.
	AnyLiteral bool

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
			Disallowed: []string{"false"},
			CWE:        "CWE-347",
			Finding:    "Token accepted without checking its signature",
			Reason:     "a token whose signature is not checked is a token anyone can write, so everything it claims is the sender's to choose",
			Rationale:  "signature verification is switched off in the call",
		},
		{
			ID: "unverified-signature", AnyCall: true, Keyword: "verify",
			Disallowed: []string{"false"},
			Qualifiers: []ArgCondition{{Keyword: "algorithms"}},
			CWE:        "CWE-347",
			Finding:    "Token accepted without checking its signature",
			Reason:     "a token whose signature is not checked is a token anyone can write, so everything it claims is the sender's to choose",
			Rationale:  "signature verification is switched off in the call",
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
			ID: "hardcoded-password", Symbol: "mongoose.connect", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
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
			ID: "hardcoded-password", Symbol: "mongoose.createConnection", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
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
			ID: "hardcoded-password", Symbol: "nodemailer.createTransport", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "ldapjs.createClient", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "ldapjs.createClient", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
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
			ID: "hardcoded-password", Symbol: "smtplib.SMTP", Keyword: "password", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "password", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the password option of a connection is given a value written in the call",
		},
		{
			ID: "hardcoded-password", Symbol: "smtplib.SMTP", Keyword: "passwd", AnyLiteral: true,
			Qualifiers: []ArgCondition{{Keyword: "passwd", NoneOf: []string{"null", "none", "undefined"}}},
			CWE:        "CWE-259",
			Finding:    "Password written into the source",
			Reason:     "a password in the source is in the repository, in every clone of it, and in the history after somebody changes it",
			Rationale:  "the passwd option of a connection is given a value written in the call",
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
		{
			// A signing key written into the source. Whatever it says, it is in the
			// repository, in every clone of it, and in the history after somebody changes
			// it -- which is what makes rotation insufficient on its own, and what makes
			// this worth reporting even when the value looks like a placeholder.
			//
			// Matching on "was it written down" rather than on what it says is also what
			// makes it precise: a key read from the environment or a vault is not a
			// literal and never matches. Nothing here inspects the string, guesses at
			// entropy, or keeps a list of what a secret looks like.
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
