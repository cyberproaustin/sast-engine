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
	// instead (ADR-005), because a match this weak has not earned a gate.
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
}

// Clears reports whether this transform neutralizes a value for a channel context.
func (s SanitizerRule) Clears(context string) bool {
	for _, c := range s.Contexts {
		if c == context {
			return true
		}
	}
	return false
}

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
						Paths:      []string{"query", "body", "params", "headers", "cookies", "files"},
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
						Paths:  []string{"args", "form", "json", "values", "headers", "cookies", "data", "files"},
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
				DeniedContext: []string{"shell", "exec-path", "sql", "html", "code"},
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
type CallShape struct {
	ID string

	// Matching, by imported symbol or by method name.
	Symbol string
	Method string

	// ArgIndex is the argument that decides it. A negative index addresses a keyword
	// argument, which the frontends record as "name=value" because `verify=False` means
	// the same thing wherever it is written.
	ArgIndex int
	// Disallowed values, compared without regard to case. A literal is required: this
	// says nothing about a value computed at runtime, and says nothing loudly rather
	// than guessing.
	Disallowed []string
	// AnyLiteral matches when the argument was written as a literal at all, whatever it
	// says. For an argument that is supposed to hold a secret, being written down IS the
	// defect and its contents are beside the point -- and the same test is what makes it
	// precise, because a secret read from the environment or a vault is not a literal
	// and never matches.
	AnyLiteral bool

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
	DependsOnUse bool

	CWE       string
	Finding   string
	Reason    string
	Rationale string
}

// Matches reports whether a literal argument value is one this shape forbids.
func (c CallShape) Matches(literal string) bool {
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
	return []CallShape{
		{
			ID: "weak-hash", Symbol: "crypto.createHash", ArgIndex: 0, DependsOnUse: true, Disallowed: weakHash,
			CWE:       "CWE-328",
			Finding:   "Weak hash algorithm",
			Reason:    "the algorithm is broken against collision, so a digest does not establish what it is used to establish",
			Rationale: "createHash() is given the algorithm by name",
		},
		{
			ID: "weak-hash", Symbol: "crypto.createHmac", ArgIndex: 0, DependsOnUse: true, Disallowed: []string{"md5", "md4", "md2"},
			CWE:     "CWE-328",
			Finding: "Weak hash algorithm",
			Reason:  "the algorithm is broken against collision, so a digest does not establish what it is used to establish",
			// HMAC-SHA1 is not currently considered broken, so it is deliberately absent
			// from this list while being present for a bare hash.
			Rationale: "createHmac() is given the algorithm by name",
		},
		{
			ID: "weak-hash", Symbol: "hashlib.new", ArgIndex: 0, DependsOnUse: true, Disallowed: weakHash,
			CWE:       "CWE-328",
			Finding:   "Weak hash algorithm",
			Reason:    "the algorithm is broken against collision, so a digest does not establish what it is used to establish",
			Rationale: "hashlib.new() is given the algorithm by name",
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
