// Package taint is the core dataflow analysis. It consumes only the IR and the
// security model, and knows nothing about any language.
//
// Every finding it produces carries the path that justifies it (ADR-006), and its
// confidence is derived from how well the call edges along that path resolved, not
// from the seriousness of the vulnerability class (ADR-005).
package taint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/reachdef"
)

// Confidence is how well the engine resolved the path it is reporting.
type Confidence string

const (
	// High: every call edge on the path resolved to a declaration.
	High Confidence = "high"
	// Medium: the path crosses at least one probable (heuristic) edge.
	Medium Confidence = "medium"
	// Low: the path crosses an unresolved dynamic dispatch.
	Low Confidence = "low"
)

// Gating reports whether a finding at this confidence may fail a pipeline.
func (c Confidence) Gating() bool { return c == High }

// Actionable reports whether this finding would gate on its own merits, setting aside the
// two questions that are about the RUN rather than about the finding: whether a baseline
// already records it, and whether it touches the change under review.
//
// The distinction matters because SARIF's level is read by every consumer as "does this
// matter", and until now it was computed from confidence alone. Confidence answers how
// sure the analysis is; this answers whether the engine would stop a build. They are
// different questions, and conflating them made the engine publish 82 findings at level
// error across ten repositories while its own gating property said false -- two thirds of
// its output overstating what it believed.
//
// Deliberately not folded into scan.Result.Gates: a finding that a baseline already knows
// is still an error, because a baseline is a record and not a suppression (ADR-014).
//
// Trust joins the list for the same reason test modules and provenance are on it. A
// management command interpolating its own argument into a shell, and a process start
// reading its own environment, are true statements about code that only somebody who
// already has the host can reach; failing a build on them would say a stranger can do
// this, which is not what the engine found. They remain reported, at warning, exactly as
// a vendored finding does -- and a scheduled job reading a column an HTTP request wrote
// still gates, because the trust travels with the SOURCE and that source is remote.
func (f Finding) Actionable() bool {
	return f.EntryAnchored && f.DependsOnUse == "" && !f.InTestModule && f.Provenance == "" &&
		f.SourceTrust() == ir.Remote && f.Confidence.Gating()
}

// SourceTrust is who could cause this finding's value to enter the program, reading an
// unstated trust as remote.
func (f Finding) SourceTrust() ir.Trust {
	if f.EntryTrust == "" {
		return ir.Remote
	}
	return f.EntryTrust
}

// Hop is one step of the evidence path.
type Hop struct {
	Loc         ir.Loc
	Description string
	Symbol      string // external symbol traversed at this hop, if any
	Literals    map[int]string
	InputArg    int    // argument carrying this path, or receiverArgIndex for a receiver
	HasInputArg bool   // distinguishes argument zero from a hop without call input metadata
	Kind        string // the IR flow kind this hop came from, when it came from a flow
	Resolution  ir.Resolution
}

// Site is another syntactic occurrence of the same weakness. The primary occurrence
// remains in Finding.SinkLoc and Finding.Path so fingerprints and every existing
// consumer stay stable; these sites retain the evidence that consolidation removes from
// the finding count.
type Site struct {
	Loc  ir.Loc
	Path []Hop
}

// composedIntoText reports whether the value was built into a larger piece of text on
// its way to the sink, rather than passed along whole.
// receiverArgIndex stands for "the value this call was made on" where an argument index
// is expected. Negative, so it can never collide with a real position.
const receiverArgIndex = -1

// leafMatches tests the LAST segment of an access path, which is where a request says
// what a field IS. A rule that names no leaves accepts every path, so this costs nothing
// where it is not used.
func leafMatches(path string, rule model.SourceRule) bool {
	if len(rule.LeafContains) == 0 && len(rule.LeafEquals) == 0 {
		return true
	}
	leaf := path
	if i := strings.LastIndexByte(leaf, '.'); i >= 0 {
		leaf = leaf[i+1:]
	}
	leaf = strings.ToLower(leaf)
	for _, veto := range rule.LeafExcept {
		if strings.Contains(leaf, strings.ToLower(veto)) {
			return false
		}
	}
	for _, want := range rule.LeafContains {
		if strings.Contains(leaf, strings.ToLower(want)) {
			return true
		}
	}
	// Exact, ignoring separators, so `is_admin` and `isAdmin` are one name.
	if len(rule.LeafEquals) > 0 {
		bare := strings.NewReplacer("_", "", "-", "").Replace(leaf)
		for _, want := range rule.LeafEquals {
			if bare == strings.ToLower(want) {
				return true
			}
		}
	}
	return false
}

// exactlyOneOf reports whether a path IS one of these rather than starting with one.
func exactlyOneOf(path string, want []string) bool {
	for _, w := range want {
		if path == w {
			return true
		}
	}
	return false
}

// composedIntoText reports whether this data was EVER built into text on its way here.
//
// Used by the channels that require a whole value. `axios.get(BASE + "/users/" + id)`
// fixes the host in the literal and leaves the caller a path segment, and that remains
// true however many functions the composed string is passed through afterwards -- so the
// question is about the whole history, and this looks at all of it.
func composedIntoText(path []Hop) bool {
	for _, h := range path {
		if h.Kind == "template" || h.Kind == "binary" {
			return true
		}
	}
	return false
}

// enclosed reports whether this value became a PART of a composite on its way here.
//
// The structural twin of composition. Where composedIntoText asks whether the caller's
// data was built into text, this asks whether it was built into an object -- and a
// channel that cares about the caller's whole object needs the answer to be no.
func enclosed(path []Hop) bool {
	for _, h := range path {
		if h.Kind == "enclose" {
			return true
		}
	}
	return false
}

// argvEnclosed includes collection extension as well as an ordinary element enclosure.
// `cmd.extend(shlex.split(query))` contributes several independent argv elements even
// though the frontend cannot name how many the split returned.
func argvEnclosed(path []Hop) bool {
	for _, h := range path {
		if h.Kind == "enclose" || h.Kind == "append" || h.Kind == "extend" {
			return true
		}
	}
	return false
}

// argvProtected proves one of the structural exceptions to argument injection on the
// particular witness path: the tainted element follows a literal `--`, begins with a
// program-authored non-dash prefix, or belongs to a program whose model says it has no
// option grammar. Absence of proof is deliberately not proof of danger for shell text;
// callers reach this only after the channel established a list enclosure.
func (e *engine) argvProtected(argvID string) bool {
	cur := argvID
	seen := map[string]bool{}
	program := ""
	for cur != "" && !seen[cur] {
		seen[cur] = true
		ed, ok := e.pred[cur]
		if !ok {
			break
		}
		// Removing every leading dash proves the same property as a literal prefix, but
		// without composing a larger string. The literal matters: lstrip() with no
		// argument removes whitespace, and lstrip("_") says nothing about options.
		method := ""
		literals := ed.literals
		if producer := e.callByResult[cur]; producer != nil {
			method = producer.Method
			literals = producer.ArgLiterals
		}
		if (method == "lstrip" || method == "strip" || strings.HasSuffix(ed.symbol, ".lstrip") ||
			strings.HasSuffix(ed.symbol, ".strip")) && literals[0] == "-" {
			return true
		}
		switch ed.kind {
		case "enclose", "append", "extend":
			if program == "" {
				program = e.firstArgLiteral(cur, map[string]bool{})
			}
			if e.literalSeparatorBefore(cur, ed.from) {
				return true
			}
			// append inserts one element. An ordinary enclosure names one element too;
			// extend inserts a collection whose members are examined on the next step.
			if ed.kind != "extend" && e.nonDashPrefix(ed.from) {
				return true
			}
		}
		cur = ed.from
	}
	return program != "" && e.m.ArgvProgramHasNoOptions(program)
}

// literalSeparatorBefore asks an ordering question over one list construction. An
// assigned or previously extended sequence is flattened because its members precede the
// new member; a nested sequence enclosed as one element is not flattened into valid argv.
func (e *engine) literalSeparatorBefore(container, member string) bool {
	for _, f := range e.flowEdgesInto[container] {
		if f.From == member {
			return false
		}
		switch f.Kind {
		case "enclose", "append":
			if v := e.ix.ValueByID[f.From]; v != nil && v.Kind == ir.ValueLiteral && v.Literal == "--" {
				return true
			}
		case "assign", "extend":
			if e.sequenceContainsLiteral(f.From, "--", map[string]bool{}) {
				return true
			}
		}
	}
	return false
}

func (e *engine) sequenceContainsLiteral(id, want string, seen map[string]bool) bool {
	if id == "" || seen[id] {
		return false
	}
	seen[id] = true
	if v := e.ix.ValueByID[id]; v != nil && v.Kind == ir.ValueLiteral {
		return v.Literal == want
	}
	for _, f := range e.flowEdgesInto[id] {
		switch f.Kind {
		case "assign", "enclose", "append", "extend":
			if e.sequenceContainsLiteral(f.From, want, seen) {
				return true
			}
		}
	}
	return false
}

// nonDashPrefix proves that composition fixes the beginning of this ONE argv element.
// A prefix beginning with '-' still names an option and is intentionally not accepted;
// a dynamic prefix is unknown and therefore cannot establish the exception.
func (e *engine) nonDashPrefix(element string) bool {
	cur := element
	seen := map[string]bool{}
	for cur != "" && !seen[cur] {
		seen[cur] = true
		ed, ok := e.pred[cur]
		if !ok {
			return false
		}
		if ed.kind == "binary" || ed.kind == "template" {
			prefix := ""
			for _, f := range e.flowEdgesInto[cur] {
				if f.From == ed.from {
					return prefix != "" && prefix[0] != '-'
				}
				lit, ok := e.literalThroughAssignments(f.From, map[string]bool{})
				if !ok {
					return false
				}
				prefix += lit
			}
		}
		cur = ed.from
	}
	return false
}

func (e *engine) literalThroughAssignments(id string, seen map[string]bool) (string, bool) {
	if id == "" || seen[id] {
		return "", false
	}
	seen[id] = true
	if v := e.ix.ValueByID[id]; v != nil && v.Kind == ir.ValueLiteral {
		return v.Literal, true
	}
	from := e.assignedFrom[id]
	if from == "" {
		return "", false
	}
	return e.literalThroughAssignments(from, seen)
}

func (e *engine) firstArgLiteral(id string, seen map[string]bool) string {
	if id == "" || seen[id] {
		return ""
	}
	seen[id] = true
	if v := e.ix.ValueByID[id]; v != nil && v.Kind == ir.ValueLiteral {
		return v.Literal
	}
	for _, f := range e.flowEdgesInto[id] {
		switch f.Kind {
		case "assign", "enclose", "append", "extend":
			if literal := e.firstArgLiteral(f.From, seen); literal != "" {
				return literal
			}
		}
	}
	return ""
}

// projected reports whether something was READ OUT of this value's source on the way
// here. The IR already records a property read as its own flow kind, so the third
// structural question needed no new fact to ask.
func projected(path []Hop) bool {
	for _, h := range path {
		if h.Kind == "property" {
			return true
		}
	}
	return false
}

// composedIntoSinkArgument reports whether the value HANDED TO THIS SINK is text the
// caller's data was built into.
//
// A different question from the one above, and the difference is the whole point.
// Scanned backwards from the sink and stopped at the first argument-passing boundary:
// once the composed text is handed to another function, whatever comes back is no longer
// that text. novu builds a Redis cache key out of a token eleven hops from the sink,
// reads the cache with it, parses the result, and passes a field of that through four
// more functions into a CQRS bus's `execute()` -- and the engine called it a SQL
// statement, because a template literal appeared somewhere in the history.
//
// Returns are deliberately NOT a boundary. Building a statement in a helper and returning
// it is ordinary, and stopping there would miss `db.query(buildQuery(req.query.name))`,
// which is a real injection in the shape real code writes it.
func composedIntoSinkArgument(path []Hop) bool {
	for i := len(path) - 1; i >= 0; i-- {
		switch path[i].Kind {
		case "template", "binary":
			return true
		case "call":
			return false
		}
	}
	return false
}

// Sanitizer records a sanitizer the taint actually passed through, and whether it
// was sufficient for the sink's context.
type Sanitizer struct {
	Symbol   string
	Loc      ir.Loc
	Clears   bool
	Note     string
	Required string // the sink context it needed to clear
}

// Finding is a reported dataflow from an untrusted source to a dangerous sink.
type Finding struct {
	Analysis string // the policy that was violated

	// The three-part judgement that produced this finding (ADR-012): a value of this
	// class reached a channel with this visibility, and policy forbids the pairing.
	DataClass  string
	ChannelID  string
	Visibility string

	Class      string
	CWE        string
	Message    string
	Confidence Confidence

	SourceLoc   ir.Loc
	SourceLabel string
	EntryPoint  string
	EntryMethod string
	EntryPath   string
	// EntryAnchored reports whether this flow reaches an entry point the engine
	// actually enumerated. An unanchored finding is not an assertion over the
	// surface (ADR-009): it is reported, but it never gates.
	EntryAnchored bool
	// EntryTrust is who could cause this value to enter the program: a remote caller,
	// an operator with a shell, or nothing outside the process at all.
	//
	// It is the SOURCE's trust, not the sink's, because that is the question a reader
	// is actually asking -- "can a stranger do this to me?" A cron job reading a column
	// an HTTP request wrote is carrying a remote caller's value, and a management
	// command interpolating its own argument into a shell is not, however identical the
	// two sinks look.
	//
	// Empty means remote, which is what every entry point was before there was anything
	// but a route. An engine must not become quieter because a frontend went silent.
	EntryTrust ir.Trust
	// InTestModule marks a finding in code that ships with the repository but does not
	// run in production. Reported, never gating: a key written into a test is in the
	// history exactly as the reason says and is still not a production credential.
	InTestModule bool
	// Provenance marks a true statement about code the repository did not hand-write as
	// lower-ranked than the same statement about application code. It remains reported:
	// vendored protocol compatibility and a generated credential table are still facts.
	Provenance ir.Provenance
	// DependsOnUse is why this finding never gates, or empty when it may.
	//
	// A single field rather than a flag per excuse, because the list grows: a weak hash
	// turns on what the digest is used for, and a relaxed CORS policy turns on whether
	// the branch it sits in runs in production. Both are facts the call does not carry,
	// both must be reported, and neither may stop a build -- but a reader deserves the
	// actual reason rather than a shared euphemism, so the sentence travels with the
	// finding instead of being reconstructed by whatever is printing it.
	//
	// Confidence is NOT used for this. Confidence means how well the call graph resolved
	// (ADR-005), and in these cases it resolved perfectly.
	DependsOnUse string
	// EntryHasNoInjectedIdentity marks a finding on an entry point that was handed no
	// caller identity, in a program where identity IS injected elsewhere. Reported so
	// that login flows, OAuth callbacks and invite redemptions can be recognized as a
	// group rather than read one at a time. It changes no judgement and no gate.
	//
	// Set only for judgements that turn on the caller's identity. A response leaking an
	// internal error is equally wrong on a login endpoint, and grouping it here would
	// suggest a remedy that does not apply to it.
	EntryHasNoInjectedIdentity bool

	SinkLoc      ir.Loc
	SinkFunction string
	SinkSymbol   string
	SinkArgIndex int
	SinkContext  string
	SinkRational string
	// Discriminator is what tells this finding apart from a SIBLING of the same rule at
	// the same sink in the same function, when nothing else in the finding does.
	//
	// A fingerprint carries no line number on purpose (ADR-014), so two findings differ
	// only by what they are ABOUT. For most rules that is already recorded: a rule that
	// judges an argument puts the argument in SourceLabel. A rule that judges the CALL
	// -- `serveIndex(...)` is a defect by existing -- records the symbol and nothing
	// else, and juice-shop's three directory listings of `/ftp`, `/encryptionkeys` and
	// `/support/logs` all came out as `ef8b2b65e604649e`. All three are separately real
	// and were separately adjudicated; one baseline entry silenced all three, and a
	// verdict about one answered for all three, so a real finding could be lost by
	// having judged its neighbour.
	//
	// Empty for every rule that already distinguishes its siblings, and the fingerprint
	// leaves it out entirely when it is empty -- so recorded verdicts keep their keys.
	Discriminator string

	Path       []Hop
	Sanitizers []Sanitizer
	// RelatedSites are other operations carrying the same rule and value origin in the
	// same function. They are evidence for this finding, not additional findings.
	RelatedSites []Site
}

// Result is the outcome of an analysis run. An analysis whose capability
// requirements are unmet is NOT APPLICABLE and reports no findings — which is a
// distinct outcome from having run and found nothing (ADR-003).
type Result struct {
	Applicable          bool
	MissingCapabilities []string
	Findings            []Finding
	Unjudged            []Unjudged
	// Skipped records policies that could not be evaluated. An unevaluated policy is
	// not a satisfied one (ADR-003).
	Skipped []SkippedPolicy
	// NoCallerIdentity holds judgements about the caller's identity made where the
	// framework handed the entry point none. Reported, never counted, never gating.
	NoCallerIdentity []Finding
	// ByClass is what each classification's dataflow found, for analyses that ask a
	// question about a value rather than about where it went.
	//
	// Exposed rather than recomputed. Which values carry a class is a question with one
	// answer, and a second analysis working it out again would be a second answer that
	// can disagree with the first.
	ByClass map[string]Classified
}

// Classified is one classification's result: the values carrying it, and where each came
// from.
type Classified struct {
	Values map[string]bool
	Origin map[string]Origin
	// Seeds are the values where the classification ENTERED the program, as opposed to
	// everywhere it subsequently reached. A rule about the classified thing itself --
	// rather than about anything a program later computed from it -- asks this.
	Seeds map[string]bool
	// Projected marks a value that was read OUT of a structure the classification
	// reached, rather than being the classified value itself.
	//
	// A credential loaded into a session and then compared field by field is the case:
	// `session.tenantId !== current` compares a tenant id, and the fact that a token was
	// handed to the function that produced the session does not make a tenant id a
	// secret. The flow analysis already answers this for its own sinks; the same answer
	// is recorded here so the analyses that read comparisons and writes can ask it too.
	Projected map[string]bool
}

// Origin is where a classified value entered the program, in the terms a finding needs.
type Origin struct {
	Label      string
	EntryPoint string
	Method     string
	Path       string
	Anchored   bool
	// Trust is who could reach the entry point this value entered through.
	Trust ir.Trust
}

// SkippedPolicy is a judgement the engine declined to make.
type SkippedPolicy struct {
	PolicyID string
	Missing  []string
}

// Unjudged is a policy that could not coherently apply to a specific flow. It is
// reported rather than dropped: "this could not be judged" is information, and
// silence would be indistinguishable from "this was fine".
type Unjudged struct {
	PolicyID   string
	EntryPoint string
	Loc        ir.Loc
	Reason     string
}

// edge records how a value became tainted, forming the evidence chain.
type edge struct {
	from       string
	kind       string
	desc       string
	loc        ir.Loc
	symbol     string
	resolution ir.Resolution
	// literals are the traversed call's literal arguments, carried so a sanitizer whose
	// rule depends on one can be decided where the flow is reconstructed rather than
	// where it was recorded.
	literals    map[int]string
	inputArg    int
	hasInputArg bool
}

type engine struct {
	ix    *ir.Index
	m     model.Model
	class model.Classification

	tainted map[string]bool
	pred    map[string]edge
	// viaTransform records whether the KEPT path to a value went through a transform the
	// model recognises, so a cleaner path arriving later can displace it.
	viaTransform map[string]bool
	seeds        map[string]seed
	skipped      map[string][]string
	unjudged     []Unjudged
	saidUnjudged map[string]bool
	// unjudgedIdentity holds findings whose judgement turned on a caller identity the
	// entry point was never given. Reported separately, never as findings.
	unjudgedIdentity []Finding

	programInjects bool

	argUses      map[string][]*ir.Call // value ID -> call sites using it as an argument
	receiverUses map[string][]*ir.Call // value ID -> call sites invoking a method on it
	callByResult map[string]*ir.Call   // result value ID -> producing call
	assignedFrom map[string]string     // value ID -> the value it was plainly assigned from
	// flowsInto is the reverse of the flow graph: value ID -> the values that flow into
	// it. The forward direction follows one witness; this one finds the SIBLINGS, which
	// is where the literal halves of a concatenation are.
	flowsInto map[string][]string
	// flowEdgesInto retains kind and source order for argv. A literal `--` only protects
	// elements after it, and reducing this graph to an unordered set would turn that
	// ordering guarantee into a guess.
	flowEdgesInto map[string][]ir.Flow
	returns       map[string][]string // function ID -> returned value IDs
	// recordFields marks a value as a RECORD HANDLE and names the columns of it that
	// carry the class: the answer a store gave, before any field has been read out of it.
	//
	// A row is not a value. It holds columns a caller filled in and columns the store
	// wrote for itself, and the read that answers with it says nothing about which is
	// which. Treating the whole row as the caller's is how the first version of the
	// second-order rule reached 2179 values in a 57k-line repository -- more than the
	// first-order class it derives from -- and produced exactly one finding, which was a
	// file path built out of an auto-increment `collection.id`.
	//
	// So a handle propagates only under a name (an assignment, a return, a parameter)
	// and becomes an ordinary classified value only where a column the program WRITES
	// there is read off it. Everything else a row can be handed to -- a template, a
	// serializer, an enclosing object -- stops, because none of those is reading a
	// column and the row is not text.
	recordFields map[string][]string
	queue        []string
}

type seed struct {
	label      string
	entryPoint string
	method     string
	path       string
	// anchored is true when entryPoint names an ENUMERATED entry point rather than
	// just the function the source was found in (ADR-009).
	anchored bool
	// unresolvedInputs names inputs injected into the entry point whose meaning the
	// frontend could not determine. A judgement that turns on what the handler was
	// given cannot be made over an input nobody could read.
	unresolvedInputs []string
	loc              ir.Loc
	// identityInjected records whether the framework handed this entry point the
	// caller's identity as a parameter. A reported fact, never a gate.
	identityInjected bool
	// trust is who could cause this value to enter the program.
	//
	// It travels with the SOURCE rather than with the sink, which is the only reading
	// that survives a second-order flow: a cron job reading a column an HTTP request
	// wrote is carrying a remote caller's value however internal the job is, and a
	// process start reading its own environment is not, however alarming the sink.
	trust ir.Trust
}

// Analyze runs source-to-sink taint propagation over a lowered program.
//
// v0 is context-insensitive: a function's parameter carries the union of taint from
// all of its call sites. This can merge a tainted call site with a safe one. It is
// the standard starting point and is corrected by call-site cloning later; until
// then it can only over-report, never under-report.
func Analyze(d *ir.IR, m model.Model) Result {
	if missing := m.TaintFlowReq.Missing(d.Frontend.Capabilities); len(missing) > 0 {
		return Result{Applicable: false, MissingCapabilities: missing}
	}

	// A variable assigned twice arrives as one value with two edges into it, and a use
	// after the second assignment must not be told about the first. Splitting happens
	// here rather than in `scan` because it is a refinement of THIS analysis: every
	// other analysis keeps reading the program the frontend produced, and the version
	// values introduced here are folded back onto the originals before the result
	// leaves (see internal/reachdef).
	d, versionOf := reachdef.Split(d)

	ix := ir.NewIndex(d)
	res := Result{Applicable: true}

	// Each class propagates independently. Sharing state would let an untrusted value
	// satisfy a sensitive-data policy and vice versa. Collection happens afterwards,
	// because some judgements are RELATIONAL — whether a record access was checked
	// against the caller's identity cannot be answered from one class alone.
	engines := make(map[string]*engine, len(m.Classifications))
	order := make([]string, 0, len(m.Classifications))

	for _, class := range m.Classifications {
		e := &engine{
			ix:            ix,
			m:             m,
			class:         class,
			tainted:       make(map[string]bool),
			pred:          make(map[string]edge),
			viaTransform:  make(map[string]bool),
			seeds:         make(map[string]seed),
			skipped:       make(map[string][]string),
			saidUnjudged:  make(map[string]bool),
			argUses:       make(map[string][]*ir.Call),
			receiverUses:  make(map[string][]*ir.Call),
			callByResult:  make(map[string]*ir.Call),
			assignedFrom:  make(map[string]string),
			flowsInto:     make(map[string][]string),
			flowEdgesInto: make(map[string][]ir.Flow),
			returns:       make(map[string][]string),
			recordFields:  make(map[string][]string),
		}
		e.programInjects = programInjectsIdentity(ix)
		e.build()
		// The classifications already propagated, for the one strategy that reads
		// another class's answer: a store read carries what was WRITTEN there. Model
		// order is the declaration of that dependency and the loop is what honours it.
		e.seedSources(engines)
		e.propagate()
		engines[class.Class] = e
		order = append(order, class.Class)
	}

	res.ByClass = make(map[string]Classified, len(engines))
	for name, e := range engines {
		as := func(sd seed) Origin {
			return Origin{
				Label:      sd.label,
				EntryPoint: sd.entryPoint,
				Method:     sd.method,
				Path:       sd.path,
				Anchored:   sd.anchored,
				Trust:      sd.trust,
			}
		}
		// Recorded for EVERY value carrying the class, not just the seeds.
		//
		// A consumer asking about a value one hop downstream of a source -- a comparison
		// against `name` where `name` came back from a lookup -- was getting a zero
		// origin, which reads as "not anchored to any entry point" and quietly demotes a
		// finding that is anchored. The seed is where the answer is, so the walk back to
		// it happens here once rather than at every call site that might need it.
		origins := make(map[string]Origin, len(e.tainted))
		proj := make(map[string]bool)
		for id := range e.tainted {
			if sd, ok := e.seeds[id]; ok {
				origins[id] = as(sd)
				continue
			}
			path, from := e.tracePath(id)
			if projected(path) {
				proj[id] = true
			}
			if from != "" {
				if sd, ok := e.seeds[from]; ok {
					origins[id] = as(sd)
				}
			}
		}
		seeds := make(map[string]bool, len(e.seeds))
		for id := range e.seeds {
			seeds[id] = true
		}

		// Every consumer outside this package speaks in the names the frontend produced,
		// so a tainted version answers to the value it was split out of. This can only
		// ADD names, never remove one: the original keeps all of its definitions, so it
		// carries whatever it carried before the split.
		values := make(map[string]bool, len(e.tainted))
		fold := func(dst map[string]bool, src map[string]bool) {
			for id := range src {
				dst[id] = true
				if orig, ok := versionOf[id]; ok {
					dst[orig] = true
				}
			}
		}
		fold(values, e.tainted)
		folded := make(map[string]bool, len(proj))
		fold(folded, proj)
		foldedSeeds := make(map[string]bool, len(seeds))
		fold(foldedSeeds, seeds)
		for id, o := range origins {
			if orig, ok := versionOf[id]; ok {
				if _, taken := origins[orig]; !taken {
					origins[orig] = o
				}
			}
		}
		res.ByClass[name] = Classified{Values: values, Origin: origins, Projected: folded, Seeds: foldedSeeds}
	}

	seen := map[string]bool{}
	for _, class := range order {
		e := engines[class]
		res.Findings = append(res.Findings, e.collect(engines, d.Frontend.Capabilities)...)
		res.NoCallerIdentity = append(res.NoCallerIdentity, e.unjudgedIdentity...)
		res.Unjudged = append(res.Unjudged, e.unjudged...)
		for id, missing := range e.skipped {
			if !seen[id] {
				seen[id] = true
				res.Skipped = append(res.Skipped, SkippedPolicy{PolicyID: id, Missing: missing})
			}
		}
	}
	sort.Slice(res.Skipped, func(i, j int) bool { return res.Skipped[i].PolicyID < res.Skipped[j].PolicyID })

	sortFindings(res.Findings)
	return res
}

func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].SinkLoc.File != f[j].SinkLoc.File {
			return f[i].SinkLoc.File < f[j].SinkLoc.File
		}
		if f[i].SinkLoc.Line != f[j].SinkLoc.Line {
			return f[i].SinkLoc.Line < f[j].SinkLoc.Line
		}
		return f[i].SourceLoc.Line < f[j].SourceLoc.Line
	})
}

func (e *engine) build() {
	for _, fn := range e.ix.IR.Functions {
		e.returns[fn.ID] = fn.Returns
		for _, c := range fn.Calls {
			for _, a := range c.Args {
				if a.ValueID != "" {
					e.argUses[a.ValueID] = append(e.argUses[a.ValueID], c)
				}
			}
			if c.ReceiverID != "" {
				e.receiverUses[c.ReceiverID] = append(e.receiverUses[c.ReceiverID], c)
			}
			if c.ResultID != "" {
				e.callByResult[c.ResultID] = c
			}
		}
		// A plain assignment is the same value under a second name. Recorded so that a
		// question about what produced a receiver survives being stored in a variable.
		for _, f := range fn.Flows {
			if f.From == "" || f.To == "" {
				continue
			}
			if f.Kind == "assign" {
				e.assignedFrom[f.To] = f.From
			}
			e.flowsInto[f.To] = append(e.flowsInto[f.To], f.From)
			e.flowEdgesInto[f.To] = append(e.flowEdgesInto[f.To], f)
		}
	}
}

// receiverMadeBy reports whether the object a method was called on came out of one of
// these calls, following plain assignments back so that
//
//	crypto.createHash("sha256").update(pw)
//
// and
//
//	const h = crypto.createHash("sha256")
//	h.update(pw)
//
// are one channel rather than two shapes. Symbols are compared on their final segment,
// because `crypto.createHash` and a destructured `createHash` name the same function.
func (e *engine) receiverMadeBy(c *ir.Call, symbols []string) bool {
	id := c.ReceiverID
	for hops := 0; hops < 8 && id != ""; hops++ {
		if prev := e.callByResult[id]; prev != nil {
			made := lastSegment(prev.Callee.Symbol)
			for _, want := range symbols {
				if made == lastSegment(want) {
					return true
				}
			}
			return false
		}
		id = e.assignedFrom[id]
	}
	return false
}

func lastSegment(symbol string) string {
	if i := strings.LastIndex(symbol, "."); i >= 0 {
		return symbol[i+1:]
	}
	return symbol
}

// seedSources marks the origins this flow cares about. Which strategy a rule uses is
// explicit, so adding an origin is a data change rather than an engine change.
//
// `prior` holds the classifications already propagated, in the order the model declares
// them. One strategy needs it: a value read back out of a store carries what was WRITTEN
// there, and what was written is another classification's answer. The dependency is a
// straight line rather than a cycle -- a store read cannot be its own writer, because the
// writer must be a value some entry point supplied.
func (e *engine) seedSources(prior map[string]*engine) {
	for _, rule := range e.class.Rules {
		switch rule.Match {
		case model.MatchValueKind:
			e.seedByValueKind(rule)
		case model.MatchGlobalProperty:
			e.seedByGlobalProperty(rule)
		case model.MatchCallResult:
			e.seedByCallResult(rule)
		case model.MatchCallMethodResult:
			e.seedByCallMethodResult(rule)
		case model.MatchProperty:
			e.seedByProperty(rule)
		case model.MatchEntryCallProperty:
			e.seedByEntryCallProperty(rule)
		case model.MatchStoreRead:
			e.seedByStoreRead(rule, prior)
		case model.MatchFunctionParamProperty:
			e.seedByFunctionParamProperty(rule)
		default:
			e.seedByEntryParamProperty(rule)
		}
	}
}

// seedByFunctionParamProperty marks data arriving at a named privileged lifecycle
// boundary whose caller is framework dispatch rather than an ordinary resolved call.
// It is intentionally exact on the function name, parameter position and property;
// treating every parameter of every lifecycle hook as caller data would manufacture a
// second request model beside the frontend's enumerated one.
func (e *engine) seedByFunctionParamProperty(rule model.SourceRule) {
	for _, fn := range e.ix.IR.Functions {
		if fn.Name != rule.Function {
			continue
		}
		param, ok := paramAt(fn, rule.ParamIndex)
		if !ok {
			continue
		}
		if len(rule.Paths) == 0 {
			entry, anchored := enclosingEntry(e.ix, fn)
			e.seeds[param.ValueID] = seed{
				label: param.Name, entryPoint: entry, anchored: anchored, loc: e.locOf(param.ValueID),
			}
			e.markTainted(param.ValueID, edge{
				desc:       fmt.Sprintf("source: %s (%s)", param.Name, e.class.Label),
				loc:        e.locOf(param.ValueID),
				resolution: ir.Resolved,
			})
			continue
		}
		for _, v := range fn.Values {
			if v.Kind != ir.ValueProperty || v.Base != param.ValueID || !matchesPath(v.Path, rule.Paths) {
				continue
			}
			label := fmt.Sprintf("%s.%s", param.Name, v.Path)
			entry, anchored := enclosingEntry(e.ix, fn)
			e.seeds[v.ID] = seed{label: label, entryPoint: entry, anchored: anchored, loc: v.Loc}
			e.markTainted(v.ID, edge{
				desc:       fmt.Sprintf("source: %s (%s)", label, e.class.Label),
				loc:        v.Loc,
				resolution: ir.Resolved,
			})
		}
	}
}

// storeWrite is one place an entry point put a caller's value into a named column of a
// named store.
type storeWrite struct {
	entryPoint string
	method     string
	path       string
	loc        ir.Loc
	fields     []string
	// trust is who reached the WRITE. A row a remote caller filled in stays a remote
	// caller's however the reader is triggered.
	trust ir.Trust
}

// seedByStoreRead marks what a lookup ANSWERED WITH, for a store some entry point writes
// another classification into.
//
// This is the second half of modelling a store, and it is the half with teeth. The first
// half is a refusal -- a read does not answer with the key it was handed -- and costs
// nothing. This one says that a value written to a database by one request and read back
// by another is still the first caller's, which is true and is also the single most
// noise-prone claim in static analysis: connect every write to every read and everything
// in a program is tainted by everything else.
//
// Four things keep it from being that, and all four are required together.
//
// The store must be NAMED. `usersRepository.findOneBy` and `prisma.client.user.create`
// both spell out which table they touch, and a write to one table does not reach a read
// of another. A store whose identity the spelling does not carry -- a `Map` the frontend
// could only type -- connects to nothing at all, because "some cache" is not an identity.
//
// The COLUMN must be named too, on both sides. This is the constraint that decides
// whether the rule is usable: without it, a route that writes a display name connects to
// a read of the primary key beside it, and an auto-increment integer becomes something a
// caller chose. Measured: the version without it reached 2179 values in linkwarden --
// more than the 1914 the first-order class it derives from reached -- and produced one
// finding, on a file path built out of `collection.id`.
//
// The write must be REACHABLE from an enumerated entry point. Seed data loaded at
// startup, a migration, and a test fixture all write rows; none of them is a caller.
//
// And the read must be somewhere the write is not. A handler that writes a row and reads
// it back is doing intra-request work the first-order analysis already follows, and
// reporting it here would be reporting the same flow twice under a scarier name.
func (e *engine) seedByStoreRead(rule model.SourceRule, prior map[string]*engine) {
	writer := prior[rule.WrittenClass]
	if writer == nil || !writer.hasSeeds() {
		return
	}

	written := map[string]storeWrite{}
	for _, fn := range e.ix.IR.Functions {
		for _, c := range fn.Calls {
			w, ok := e.m.StoreWriteAt(c.Callee.Symbol, c.Method, c.ReceiverType)
			if !ok || w.Medium != rule.Medium {
				continue
			}
			name := w.StoreName(c.Callee.Symbol, c.Method)
			if name == "" {
				continue
			}
			// The columns this write NAMES. A spread can hide others, which costs
			// recall and not precision: a column the frontend did see is one the
			// program writes there, whatever else the call may also carry.
			fields := w.WrittenFields(c.ArgLiterals)
			if len(fields) == 0 {
				continue
			}
			if !writer.callCarries(c, w.ValueArg) {
				continue
			}
			entry, anchored := enclosingEntry(e.ix, fn)
			if !anchored {
				continue
			}
			prev, seen := written[name]
			if !seen {
				site := storeWrite{entryPoint: entry, loc: c.Loc, fields: fields}
				if ep, ok := EntryOf(e.ix, fn); ok {
					site.trust = ep.TrustLevel()
				}
				if ep, ok := e.ix.EntryByFunc[fn.ID]; ok {
					site.method, site.path = ep.Detail["method"], ep.Detail["path"]
				}
				written[name] = site
				continue
			}
			for _, f := range fields {
				if !contains(prev.fields, f) {
					prev.fields = append(prev.fields, f)
				}
			}
			written[name] = prev
		}
	}
	if len(written) == 0 {
		return
	}

	for _, fn := range e.ix.IR.Functions {
		for _, c := range fn.Calls {
			if c.ResultID == "" {
				continue
			}
			r, ok := e.m.StoreReadAt(c.Callee.Symbol, c.Method, c.ReceiverType)
			if !ok || r.Medium != rule.Medium {
				continue
			}
			name := r.StoreName(c.Callee.Symbol, c.Method)
			if name == "" {
				continue
			}
			w, ok := written[name]
			if !ok {
				continue
			}
			entry, anchored := enclosingEntry(e.ix, fn)
			if entry == w.entryPoint {
				continue
			}
			label := fmt.Sprintf("the %s store, written by %s", name, describeWriter(w))
			// The WRITER's trust, not the reader's: this value is whatever the caller
			// who stored it was.
			sd := seed{label: label, entryPoint: entry, anchored: anchored, loc: c.Loc, trust: w.trust}
			if ep, ok := EntryOf(e.ix, fn); ok {
				sd.unresolvedInputs = ep.UnresolvedParams
				sd.identityInjected = injectsIdentity(e.ix, ep)
			}
			if ep, ok := e.ix.EntryByFunc[fn.ID]; ok {
				sd.method, sd.path = ep.Detail["method"], ep.Detail["path"]
			}
			e.seeds[c.ResultID] = sd
			e.recordFields[c.ResultID] = w.fields
			e.markTainted(c.ResultID, edge{
				desc:       fmt.Sprintf("source: %s (%s)", label, e.class.Label),
				loc:        c.Loc,
				resolution: c.Callee.Resolution,
			})
		}
	}
}

// describeWriter names the entry point that put the value there, which is the half of a
// second-order finding a reader cannot reconstruct from the sink.
func describeWriter(w storeWrite) string {
	if w.method != "" || w.path != "" {
		return strings.TrimSpace(w.method + " " + w.path)
	}
	if w.entryPoint != "" {
		return w.entryPoint
	}
	return w.loc.String()
}

// callCarries reports whether this call was handed a classified value in the argument a
// store rule names, or in any argument when it names none.
func (e *engine) callCarries(c *ir.Call, index int) bool {
	for _, a := range c.Args {
		if a.ValueID == "" || !e.tainted[a.ValueID] {
			continue
		}
		if index < 0 || a.At(index) {
			return true
		}
	}
	return false
}

// seedByEntryCallProperty marks a property read off the result of a call the handler
// made with its own request.
//
//	const { auth, body, error } = await parseRequest(request, schema);
//
// A framework that hands the handler a bare `Request` gives it nowhere to hang an
// identity, so the application parses and authenticates in a helper of its own and
// destructures the answer. The helper belongs to the application, so no symbol can be
// named for it; what is named is the shape, and the two halves that keep it narrow are
// that the call was handed one of the handler's OWN parameters and that the property is
// one of the leaves the rule lists.
func (e *engine) seedByEntryCallProperty(rule model.SourceRule) {
	for _, ep := range e.ix.IR.EntryPoints {
		if rule.EntryKind != ep.Kind {
			continue
		}
		if rule.Framework != "" && ep.Framework != "" && rule.Framework != ep.Framework {
			continue
		}
		fn := e.ix.FuncByID[ep.FunctionID]
		if fn == nil {
			continue
		}
		param, ok := paramAt(fn, rule.ParamIndex)
		if !ok {
			continue
		}
		// The results of calls this handler made with that parameter. A call that was
		// handed the request is the only kind that can have parsed it.
		fromRequest := map[string]bool{}
		for _, c := range fn.Calls {
			if c.ResultID == "" {
				continue
			}
			for _, a := range c.Args {
				if a.ValueID == param.ValueID {
					fromRequest[c.ResultID] = true
				}
			}
		}
		if len(fromRequest) == 0 {
			continue
		}
		for _, v := range fn.Values {
			if v.Kind != ir.ValueProperty || !fromRequest[v.Base] {
				continue
			}
			if !matchesPath(v.Path, rule.Paths) || !leafMatches(v.Path, rule) {
				continue
			}
			label := v.Path
			e.seeds[v.ID] = seed{
				label:            label,
				entryPoint:       describeEntry(ep),
				method:           ep.Detail["method"],
				path:             ep.Detail["path"],
				anchored:         true,
				unresolvedInputs: ep.UnresolvedParams,
				loc:              ep.Loc,
				identityInjected: injectsIdentity(e.ix, &ep),
				trust:            ep.TrustLevel(),
			}
			e.markTainted(v.ID, edge{
				desc:       fmt.Sprintf("source: %s (%s)", label, e.class.Label),
				loc:        v.Loc,
				resolution: ir.Resolved,
			})
		}
	}
}

// seedByValueKind marks every value the frontend lowered with a given kind, e.g. the
// binding of a catch clause.
func (e *engine) seedByValueKind(rule model.SourceRule) {
	for _, fn := range e.ix.IR.Functions {
		for _, v := range fn.Values {
			if string(v.Kind) != rule.ValueKind {
				continue
			}
			label := v.Name
			if label == "" {
				label = rule.ValueKind
			}
			entry, anchored := enclosingEntry(e.ix, fn)
			sd := seed{label: label, entryPoint: entry, anchored: anchored}
			if ep, ok := EntryOf(e.ix, fn); ok {
				sd.unresolvedInputs, sd.loc = ep.UnresolvedParams, ep.Loc
				sd.identityInjected = injectsIdentity(e.ix, ep)
				sd.trust = ep.TrustLevel()
			}
			e.seeds[v.ID] = sd
			if ep, ok := e.ix.EntryByFunc[fn.ID]; ok {
				sd := e.seeds[v.ID]
				sd.method, sd.path = ep.Detail["method"], ep.Detail["path"]
				e.seeds[v.ID] = sd
			}
			e.markTainted(v.ID, edge{
				desc:       fmt.Sprintf("source: %s (%s)", label, e.class.Label),
				loc:        v.Loc,
				resolution: ir.Resolved,
			})
		}
	}
}

// globalPathOf walks a chain of property reads back to a named global and returns the
// whole access path it spells out, or false when the chain starts somewhere else.
//
// The walk crosses assignments, which is the difference between seeing a request field
// and not seeing it. Both of these read the same field:
//
//	request.json["password"]
//	data = request.json
//	data["password"]
//
// and only the first arrives as one value with the whole path on it. The second is two
// property reads with a local in between, and a walk that stopped at the local read the
// path as `password` on something unknown -- so every rule that names a LEAF was blind to
// the spelling that most code actually uses. Following the assignment back rejoins the
// halves.
//
// Bounded and cycle-guarded, because an IR is data and this walks it.
func (e *engine) globalPathOf(v *ir.Value, symbol string) (string, bool) {
	seen := map[string]bool{}
	path := v.Path
	cur := v
	for cur != nil && !seen[cur.ID] {
		seen[cur.ID] = true
		if cur.Kind == "global" {
			return path, cur.Name == symbol
		}
		next := cur.Base
		if next == "" {
			next = e.assignedFrom[cur.ID]
		}
		if next == "" {
			return path, false
		}
		cur = e.ix.ValueByID[next]
		if cur == nil {
			return path, false
		}
		// The segments a base already carries are not repeated. A frontend that
		// accumulated the whole path onto the leaf hands over `json.password` with a
		// base of `json`, and prepending it again would invent a field nobody read.
		if cur.Path != "" && !strings.HasPrefix(path, cur.Path+".") && path != cur.Path {
			path = cur.Path + "." + path
		}
	}
	return path, false
}

// rootsAtGlobal reports whether a chain of property reads starts at a named global.
func (e *engine) rootsAtGlobal(v *ir.Value, symbol string) bool {
	_, ok := e.globalPathOf(v, symbol)
	return ok
}

// seedByCallResult marks what a named call RETURNS.
//
// The match kind was declared and never implemented, so a rule using it fell through to
// the entry-parameter seeder and matched nothing at all -- quietly, which is the worst way
// for a rule to be wrong. It exists for provenance: what makes a weak random number a
// weakness is not the call but where the number ends up, and that question starts here.
func (e *engine) seedByCallResult(rule model.SourceRule) {
	for _, fn := range e.ix.IR.Functions {
		for _, c := range fn.Calls {
			if c.Callee.Symbol != rule.Symbol || c.ResultID == "" {
				continue
			}
			// A number the call was WRITTEN with. A length computed at runtime is not
			// written in the call and is not matched, which is the same line every other
			// literal-reading rule here draws.
			if rule.ArgBelow != nil && !belowLiteral(c.ArgLiterals[rule.ArgBelowIndex], *rule.ArgBelow) {
				continue
			}
			// A string the call was WRITTEN with, deciding which class the result
			// belongs to. `createHash("md5")` says what it is; `createHash(algorithm)`
			// does not, and is not guessed at.
			label := rule.Symbol + "()"
			if len(rule.ArgOneOf) > 0 {
				written, ok := c.ArgLiterals[0]
				if !ok || !writtenOneOf(written, rule.ArgOneOf) {
					continue
				}
				label = fmt.Sprintf("%s(%q)", rule.Symbol, strings.TrimSpace(written))
			}
			entry, anchored := enclosingEntry(e.ix, fn)
			sd := seed{label: label, entryPoint: entry, anchored: anchored}
			if ep, ok := EntryOf(e.ix, fn); ok {
				sd.unresolvedInputs, sd.loc = ep.UnresolvedParams, ep.Loc
				sd.identityInjected = injectsIdentity(e.ix, ep)
				sd.trust = ep.TrustLevel()
			}
			if ep, ok := e.ix.EntryByFunc[fn.ID]; ok {
				sd.method, sd.path = ep.Detail["method"], ep.Detail["path"]
			}
			e.seeds[c.ResultID] = sd
			e.markTainted(c.ResultID, edge{
				desc:       fmt.Sprintf("source: %s (%s)", label, e.class.Label),
				loc:        c.Loc,
				resolution: c.Callee.Resolution,
			})
		}
	}
}

// seedByCallMethodResult is intentionally separate from symbol matching. The timing rule
// needs one Tornado method, not a semantic change to every existing call-result source.
func (e *engine) seedByCallMethodResult(rule model.SourceRule) {
	for _, fn := range e.ix.IR.Functions {
		for _, c := range fn.Calls {
			if c.ResultID == "" || c.Method != rule.Method {
				continue
			}
			label := rule.Method + "()"
			entry, anchored := enclosingEntry(e.ix, fn)
			sd := seed{label: label, entryPoint: entry, anchored: anchored, loc: c.Loc}
			if ep, ok := EntryOf(e.ix, fn); ok {
				sd.entryPoint, sd.anchored = describeEntry(*ep), true
				sd.method, sd.path = ep.Detail["method"], ep.Detail["path"]
				sd.trust = ep.TrustLevel()
			}
			e.seeds[c.ResultID] = sd
			e.markTainted(c.ResultID, edge{
				desc:       fmt.Sprintf("source: %s (%s)", label, e.class.Label),
				loc:        c.Loc,
				resolution: c.Callee.Resolution,
			})
		}
	}
}

// seedByProperty marks a value whose property leaf states its security role. This is
// deliberately not a local-name classifier: locals named token and secret are abundant,
// while a property access is the program selecting a field with that role from a runtime
// object. No finding rests on this class alone; a decision rule must relate it to caller
// input before it can say anything.
func (e *engine) seedByProperty(rule model.SourceRule) {
	for _, fn := range e.ix.IR.Functions {
		for _, v := range fn.Values {
			if v.Kind != ir.ValueProperty || !leafMatches(v.Path, rule) {
				continue
			}
			entry, anchored := enclosingEntry(e.ix, fn)
			sd := seed{label: v.Path, entryPoint: entry, anchored: anchored, loc: v.Loc}
			if ep, ok := EntryOf(e.ix, fn); ok {
				sd.entryPoint, sd.anchored = describeEntry(*ep), true
				sd.method, sd.path = ep.Detail["method"], ep.Detail["path"]
				sd.trust = ep.TrustLevel()
			}
			e.seeds[v.ID] = sd
			e.markTainted(v.ID, edge{
				desc:       fmt.Sprintf("source: %s (%s)", v.Path, e.class.Label),
				loc:        v.Loc,
				resolution: ir.Resolved,
			})
		}
	}
}

// writtenOneOf reports whether a literal argument is one of a set of strings, compared
// without regard to case. An argument that was not written down is not one of anything.
func writtenOneOf(literal string, want []string) bool {
	literal = strings.TrimSpace(literal)
	for _, w := range want {
		if strings.EqualFold(literal, w) {
			return true
		}
	}
	return false
}

// belowLiteral reports whether a literal was a number smaller than a threshold. An
// argument that was not written as a number is not below anything.
func belowLiteral(literal string, threshold int) bool {
	n, err := strconv.Atoi(strings.TrimSpace(literal))
	return err == nil && n < threshold
}

// seedByGlobalProperty marks property accesses on a framework-bound global, which is
// how frameworks that do not pass a request object into the handler expose one.
func (e *engine) seedByGlobalProperty(rule model.SourceRule) {
	for _, fn := range e.ix.IR.Functions {
		for _, v := range fn.Values {
			if v.Kind != ir.ValueProperty {
				continue
			}
			// The base chain is walked rather than checked one link back, and the whole
			// path it spells out is what the rule is tested against. `request.form` has
			// the global as its base and `request.form["password"]` has `request.form`,
			// so a one-link check saw the first and never the second -- which is every
			// leaf-named rule blind on the nested form, and the nested form is how a
			// request field is actually written.
			path, rooted := e.globalPathOf(v, rule.Symbol)
			if !rooted || !matchesPath(path, rule.Paths) {
				continue
			}
			if rule.ExactPath && !exactlyOneOf(path, rule.Paths) {
				continue
			}
			if !leafMatches(path, rule) {
				continue
			}
			label := fmt.Sprintf("%s.%s", rule.Symbol, path)
			entry, anchored := enclosingEntry(e.ix, fn)
			sd := seed{label: label, entryPoint: entry, anchored: anchored}
			if ep, ok := EntryOf(e.ix, fn); ok {
				sd.unresolvedInputs, sd.loc = ep.UnresolvedParams, ep.Loc
				sd.identityInjected = injectsIdentity(e.ix, ep)
				sd.trust = ep.TrustLevel()
			}
			e.seeds[v.ID] = sd
			if ep, ok := e.ix.EntryByFunc[fn.ID]; ok {
				sd := e.seeds[v.ID]
				sd.method, sd.path = ep.Detail["method"], ep.Detail["path"]
				e.seeds[v.ID] = sd
			}
			e.markTainted(v.ID, edge{
				desc:       fmt.Sprintf("source: %s (%s)", label, e.class.Label),
				loc:        v.Loc,
				resolution: ir.Resolved,
			})
		}
	}
}

func (e *engine) seedByEntryParamProperty(rule model.SourceRule) {
	for _, ep := range e.ix.IR.EntryPoints {
		fn := e.ix.FuncByID[ep.FunctionID]
		if fn == nil {
			continue
		}
		{
			if rule.EntryKind != ep.Kind {
				continue
			}
			if rule.Framework != "" && ep.Framework != "" && rule.Framework != ep.Framework {
				continue
			}
			param, ok := paramAt(fn, rule.ParamIndex)
			if !ok {
				continue
			}
			for _, v := range fn.Values {
				if v.Kind != ir.ValueProperty || v.Base != param.ValueID {
					continue
				}
				if !matchesPath(v.Path, rule.Paths) {
					continue
				}
				if !leafMatches(v.Path, rule) {
					continue
				}
				label := fmt.Sprintf("%s.%s", param.Name, v.Path)
				e.seeds[v.ID] = seed{
					label:      label,
					entryPoint: describeEntry(ep),
					method:     ep.Detail["method"],
					path:       ep.Detail["path"],
					// This rule iterates enumerated entry points, so anything it
					// seeds is anchored by construction.
					anchored:         true,
					unresolvedInputs: ep.UnresolvedParams,
					loc:              ep.Loc,
					identityInjected: injectsIdentity(e.ix, &ep),
					trust:            ep.TrustLevel(),
				}
				e.markTainted(v.ID, edge{
					desc:       fmt.Sprintf("source: %s (%s)", label, e.class.Label),
					loc:        v.Loc,
					resolution: ir.Resolved,
				})
			}
		}
	}
}

func (e *engine) propagate() {
	for len(e.queue) > 0 {
		id := e.queue[0]
		e.queue = e.queue[1:]

		for _, f := range e.ix.FlowsFrom[id] {
			carry, stillRecord := e.recordHopCarries(id, f)
			if !carry {
				continue
			}
			e.markTainted(f.To, edge{
				from:       id,
				kind:       f.Kind,
				desc:       e.describeFlow(f),
				loc:        f.Loc,
				resolution: ir.Resolved,
			})
			if stillRecord {
				e.carriesRecord(id, f.To)
			}
		}

		for _, c := range e.argUses[id] {
			e.throughCall(id, c)
		}

		// A method called ON a row does not answer with a column of it. `row.toJSON()`
		// and `row.toString()` are the shapes, and neither is a caller reading a field.
		if !e.hasRecord(id) {
			for _, c := range e.receiverUses[id] {
				e.throughReceiver(id, c)
			}
		}

		if fn := e.ix.OwnerOfValue[id]; fn != nil && contains(e.returns[fn.ID], id) {
			// A function that returns what it was GIVEN returns it only to the callers
			// that gave it something.
			//
			// Propagating a tainted return to every call site is how a request value ends
			// up four frames below the handler in a JSON path parser: one route passes a
			// role into a shared helper, and every other caller of that helper -- and
			// everything they compute from the answer -- is tainted too. Measured on
			// directus, that single imprecision produced 118 findings from one route.
			//
			// The condition is not context sensitivity, which is a much larger thing. It
			// is the cheapest half of it: if the taint arrived through a PARAMETER, only
			// the call sites that passed something tainted receive the answer. Taint that
			// arose inside the function -- it read a request global, it opened a file --
			// belongs to every caller, and is untouched.
			fromParam := e.taintEnteredViaParam(fn, id)
			for _, site := range e.ix.CallSitesOf[fn.ID] {
				if site.ResultID == "" {
					continue
				}
				if fromParam && !e.callSitePassesTaint(site) {
					continue
				}
				e.carriesRecord(id, site.ResultID)
				e.markTainted(site.ResultID, edge{
					from:       id,
					desc:       fmt.Sprintf("returned from %s()", fn.Name),
					kind:       "return",
					loc:        site.Loc,
					resolution: site.Callee.Resolution,
				})
			}
		}
	}
}

// recordHopCarries decides what a RECORD HANDLE may flow along.
//
// Two answers only. A hop that renames the row -- an assignment, a return -- carries the
// handle. A hop that READS A COLUMN carries the class itself, and only for a column the
// program writes into that store from a request; every other column of the row is the
// store's own answer and is not the caller's. Everything else stops: a row interpolated
// into a template is not text a caller wrote, and a row enclosed in a response object is
// not a field of it.
func (e *engine) recordHopCarries(from string, f ir.Flow) (carry bool, stillRecord bool) {
	fields := e.recordFields[from]
	if len(fields) == 0 {
		return true, false
	}
	switch f.Kind {
	case "assign", "return":
		return true, true
	case "property":
		v := e.ix.ValueByID[f.To]
		if v == nil {
			return false, false
		}
		leaf := v.Path
		if i := strings.LastIndex(leaf, "."); i >= 0 {
			leaf = leaf[i+1:]
		}
		return contains(fields, model.NormalizeFieldName(leaf)), false
	}
	return false, false
}

// taintEnteredViaParam reports whether this value's taint came in through one of the
// function's own parameters, as opposed to arising inside it.
func (e *engine) taintEnteredViaParam(fn *ir.Function, id string) bool {
	params := make(map[string]bool, len(fn.Params))
	for _, p := range fn.Params {
		params[p.ValueID] = true
	}
	if len(params) == 0 {
		return false
	}
	seen := map[string]bool{}
	cur := id
	for hops := 0; hops < 64 && cur != "" && !seen[cur]; hops++ {
		seen[cur] = true
		if params[cur] {
			return true
		}
		ed, ok := e.pred[cur]
		if !ok {
			return false
		}
		cur = ed.from
	}
	return false
}

// callSitePassesTaint reports whether this call site handed the callee anything already
// classified -- an argument, or the object it was called on.
func (e *engine) callSitePassesTaint(c *ir.Call) bool {
	if c.ReceiverID != "" && e.tainted[c.ReceiverID] {
		return true
	}
	for _, a := range c.Args {
		if a.ValueID != "" && e.tainted[a.ValueID] {
			return true
		}
	}
	return false
}

// throughCall propagates taint from a tainted argument into a call site: into the
// callee's parameter when the target is known, or into the result when it is not.
func (e *engine) throughCall(argValueID string, c *ir.Call) {
	for _, a := range c.Args {
		if a.ValueID != argValueID {
			continue
		}
		switch c.Callee.Kind {
		case "local":
			callee := e.ix.FuncByID[c.Callee.FunctionID]
			if callee == nil {
				continue
			}
			param, ok := a.BoundParam(callee)
			if !ok {
				continue
			}
			binding := fmt.Sprintf("argument %d", a.Index)
			if a.Name != "" {
				binding = fmt.Sprintf("argument `%s`", a.Name)
			}
			e.carriesRecord(argValueID, param.ValueID)
			e.markTainted(param.ValueID, edge{
				from: argValueID,
				desc: fmt.Sprintf("passed as %s to %s()", binding, callee.Name),
				// The callee's own NAME, so a sanitizer can recognise a transform an
				// application defined for itself. novu writes its own `escapeRegExp` and
				// interpolates the result into a pattern, which is the correct way to
				// search for a literal string -- and every sanitizer here matched imported
				// symbols only, so a local one was invisible and the flow read as
				// catastrophic backtracking.
				symbol:     callee.Name,
				kind:       "call",
				loc:        c.Loc,
				resolution: c.Callee.Resolution,
			})
		default:
			// External or unresolved: taint the result. Whether a traversed
			// sanitizer actually helps is decided at the sink, where the required
			// context is known.
			if c.ResultID == "" {
				continue
			}
			// Unless the call is a READ FROM A STORE, in which case the argument is
			// the key and the result is whatever was filed under it. A lookup answers
			// with what was WRITTEN, and what was written is a separate question with a
			// separate provenance -- one this engine now asks separately.
			//
			// Without this, taint flowed from the key a lookup was given into the value
			// it returned, so anything a caller could NAME became something a caller
			// had WRITTEN. Three of misskey's false positives rested on this one step,
			// including a 49-hop path from an ActivityPub queue processor onto raw SQL
			// where the SQL is genuinely raw and the taint is not there at all.
			if _, ok := e.m.StoreReadAt(c.Callee.Symbol, c.Method, c.ReceiverType); ok {
				continue
			}
			// A ROW handed to a call the frontend could not read does not come back out
			// of it as a caller's value. `JSON.stringify(row)` and `escape(row)` are the
			// two shapes, and the second is the fix.
			if e.hasRecord(argValueID) {
				continue
			}
			e.markTainted(c.ResultID, edge{
				from:        argValueID,
				desc:        fmt.Sprintf("through %s()", displaySymbol(c.Callee)),
				loc:         c.Loc,
				symbol:      c.Callee.Symbol,
				literals:    c.ArgLiterals,
				inputArg:    a.Index,
				hasInputArg: true,
				resolution:  c.Callee.Resolution,
			})
		}
	}
}

// throughReceiver propagates taint from the object a method was called on: into the
// result (`s.trim()` keeps the taint) and, for higher-order methods, into the
// callback's parameter (`arr.forEach(h => ...)`, `p.then(v => ...)`).
func (e *engine) throughReceiver(receiverID string, c *ir.Call) {
	if rule, ok := e.m.CallbackFor(c.Method); ok {
		if arg, found := argAt(c, rule.CallbackArg); found && arg.FunctionID != "" {
			if callback := e.ix.FuncByID[arg.FunctionID]; callback != nil {
				if param, ok := paramAt(callback, rule.CallbackParam); ok {
					e.markTainted(param.ValueID, edge{
						from:       receiverID,
						desc:       fmt.Sprintf("into the %s() callback as `%s` (%s)", c.Method, param.Name, rule.Note),
						loc:        c.Loc,
						resolution: c.Callee.Resolution,
					})
				}
			}
		}
	}

	// A method on tainted data generally returns tainted data. Only external
	// receivers are handled here; a local callee's return is already propagated
	// through its own return values.
	if c.Callee.Kind == "local" || c.ResultID == "" {
		return
	}
	e.markTainted(c.ResultID, edge{
		from:        receiverID,
		desc:        fmt.Sprintf("through .%s() on tainted data", c.Method),
		loc:         c.Loc,
		symbol:      c.Callee.Symbol,
		inputArg:    receiverArgIndex,
		hasInputArg: true,
		resolution:  c.Callee.Resolution,
	})
}

// collect walks every sink call site and reports those reached by tainted data.
// hasSeeds reports whether this class was observed anywhere in the program. A class
// with no seeds is one this engine has no vocabulary for in this codebase.
func (e *engine) hasSeeds() bool { return len(e.seeds) > 0 }

func (e *engine) collect(all map[string]*engine, caps ir.Capabilities) []Finding {
	var out []Finding
	for _, fn := range e.ix.IR.Functions {
		for _, c := range fn.Calls {
			for _, ch := range e.m.ChannelsMatching(c.Callee.Symbol, c.Method) {
				// A method-name channel only counts when its receiver really is the
				// object it describes. Without this, `.json()` on any value in the
				// program would be an HTTP response.
				if ch.ReceiverIsEntryParam >= 0 && e.receiverRootParam(c) != ch.ReceiverIsEntryParam {
					continue
				}
				if ch.Symbol != "" && c.Callee.Kind != "external" {
					continue
				}
				// A rule about a method only one language has.
				if ch.Language != "" && !strings.EqualFold(ch.Language, e.ix.IR.Frontend.Name) {
					continue
				}
				// A rule about the PATTERN this call uses rather than about the call.
				if ch.PatternArg != nil && !model.CatastrophicPattern(e.patternAt(c, *ch.PatternArg)) {
					continue
				}
				// A method name with no identity of its own, narrowed by what made the
				// object it was called on.
				if len(ch.ReceiverFrom) > 0 && !e.receiverMadeBy(c, ch.ReceiverFrom) {
					continue
				}
				// The negative form preserves a broad method channel unless receiver
				// provenance positively identifies a different operation. Unknown is not
				// excluded: a missing producer is no basis for dropping an ORM update.
				if len(ch.ReceiverNotFrom) > 0 && e.receiverMadeBy(c, ch.ReceiverNotFrom) {
					continue
				}
				// The language's own containers are not stores of shared records.
				// Only a positive answer disqualifies: a frontend that cannot type
				// its receivers leaves this empty, and empty is not "not builtin".
				// Neither the language's own containers nor an imported module is a
				// store of records shared between callers.
				if ch.RequiresExternalReceiver &&
					(c.ReceiverTypeOrigin == "builtin" || c.ReceiverTypeOrigin == "module") {
					continue
				}
				// Writing into a fresh object literal is making a copy, not writing a
				// record. The frontend already says which arguments are object literals
				// it read in full, which is exactly the question.
				if ch.TargetArg != nil && c.OptionsEnumerated(*ch.TargetArg) {
					continue
				}
				// A call that must actually be handed something.
				if ch.RequiresArgs > 0 && c.ArgCount < ch.RequiresArgs {
					continue
				}
				// A destination that is only dangerous in its default configuration. A
				// call that was handed more than this was configured, and how it was
				// configured is not visible here.
				if ch.MaxArgs > 0 && c.ArgCount > ch.MaxArgs {
					continue
				}
				// A destination that is only dangerous when configured to be. An XML
				// parser resolves entities when asked and not otherwise.
				skip := false
				for _, q := range ch.Qualifiers {
					if !q.Holds(c.ArgLiterals) {
						skip = true
						break
					}
				}
				if skip {
					continue
				}
				// A channel identified by what it is called on. `user.save()` and
				// `uploaded.save(dest)` are the same method name and nothing else in
				// common; only one of them is called on data the caller sent.
				if ch.RequiresUntrustedReceiver && !e.tainted[c.ReceiverID] {
					continue
				}
				// And the receiver must be the classified value itself, for a channel
				// that says so. A service object a shared helper returned is not an
				// upload however tainted it looks.
				if ch.RequiresUnprojectedReceiver {
					path, _ := e.tracePath(c.ReceiverID)
					if projected(path) {
						continue
					}
				}
				// Reaching a channel is not itself a defect. Policy decides whether
				// THIS class reaching THIS channel is forbidden (ADR-012).
				policies := e.m.PoliciesFor(e.class.Class, ch)
				if len(policies) == 0 {
					continue
				}
				// A channel with no argument index is about the RECEIVER: what the call
				// was made ON is the value that reached it. A caller-supplied format
				// string is called, not passed.
				reaching := ch.ArgIndex
				if len(reaching) == 0 && ch.RequiresUntrustedReceiver {
					reaching = []int{receiverArgIndex}
				}
				for _, idx := range reaching {
					arg, ok := argAt(c, idx)
					if idx == receiverArgIndex {
						arg, ok = ir.Arg{Index: receiverArgIndex, ValueID: c.ReceiverID}, c.ReceiverID != ""
					}
					if !ok || !e.tainted[arg.ValueID] {
						continue
					}
					for _, p := range policies {
						if missing := p.Requires.Missing(caps); len(missing) > 0 {
							e.skipped[p.ID] = missing
							continue
						}
						if p.RequiresRelationTo != "" {
							other := all[p.RequiresRelationTo]

							// A policy satisfiable ONLY by relating to another class
							// cannot be evaluated where that class is not observable.
							//
							// `unowned-record-access` is satisfied by relating a
							// selector to the caller's identity. Identity is seeded
							// from framework-specific shapes — `req.user` on Express,
							// `g.user` on Flask — and a framework with no such rule
							// yields no identity anywhere in the program. The policy
							// then cannot be satisfied by any code, however careful,
							// and reports every record access as unowned. That is a
							// statement about this engine's vocabulary, not about the
							// application (ADR-003).
							//
							// The test is empirical and program-wide: did anything at
							// all seed this class? Program-wide is what keeps it sound.
							// Asking per-flow would silence the primary defect, because
							// a handler with no ownership check contains no identity by
							// definition — an earlier version made exactly that mistake
							// and the express-idor corpus caught it.
							// An entry point given an input the frontend could not
							// read cannot support the conclusion that identity was
							// never consulted — the unread input may be exactly that.
							// Per entry point, not program-wide: the rest of the
							// application is still judged normally.
							if sd := e.seeds[e.originOf(arg.ValueID)]; len(sd.unresolvedInputs) > 0 {
								// One statement per entry point, not per flow: a
								// handler with six queries has one reason.
								key := p.ID + "\x00" + sd.entryPoint
								if !e.saidUnjudged[key] {
									e.saidUnjudged[key] = true
									e.unjudged = append(e.unjudged, Unjudged{
										PolicyID:   p.ID,
										EntryPoint: sd.entryPoint,
										Loc:        sd.loc,
										Reason: "an input injected here could not be resolved (" +
											strings.Join(sd.unresolvedInputs, ", ") +
											"); whatever defines it is not in the scanned tree",
									})
								}
								continue
							}
							if other == nil || !other.hasSeeds() {
								e.skipped[p.ID] = []string{
									"no source for " + p.RequiresRelationTo + " in this program",
								}
								continue
							}

							// A selection CONSTRAINED by the caller's identity is
							// scoped: `{where: {id, userId: user.id}}` cannot reach a
							// record the caller does not own, and no comparison appears
							// anywhere. This is how multi-tenant code is normally
							// written — the query carries the tenant rather than the
							// handler checking it — and a policy that only recognizes a
							// check calls every one of those a missing ownership check.
							//
							// Whether the constraint is expressed as a test before the
							// operation or as part of the selection is a matter of
							// style, not of security, so both satisfy the policy.
							//
							// The identity need not sit inside the selector. Passing it
							// alongside — `webhookService.delete(id, workspace.id)` —
							// is the same statement made with two arguments instead of
							// one nested object, and the operation is equally unable to
							// reach a record the caller does not own.
							//
							// Known looseness: the relation is "reached the same
							// operation", so identity carried as payload rather than as
							// scope — `update(id, {updatedBy: user.id})` — counts as if
							// it constrained the selection. Narrowing that needs
							// per-field tracking at the selector, which the IR does not
							// carry today.
							if e.operationCarries(c, other) {
								continue
							}

							// The guard may live anywhere the data travelled, not
							// only in the function holding the operation. Real code
							// checks in the caller and operates in a private helper.
							chain := e.functionsOnPath(arg.ValueID, fn)

							// NOTE: an earlier version skipped the judgement when no
							// actor identity appeared on the path, reasoning that you
							// cannot compare against something absent. That silences
							// the primary case — a handler with NO ownership check has
							// no actor identity in it, which is exactly what makes it
							// a defect. Distinguishing a login endpoint from an
							// unauthenticated data endpoint is not derivable from
							// code, so it belongs in declared policy (ADR-011).
							if effectivelyRelated(chain, c, other) {
								continue
							}
						}
						if f, reported := e.buildFinding(c, ch, p, arg); reported {
							// A judgement about the caller's identity, on an entry point
							// the framework handed no identity, is not a judgement. It
							// is the policy restating that it had nothing to compare
							// against, and it is right every time and useful never.
							//
							// Not a guess. 42 of these were adjudicated by hand against
							// the source of sixteen production repositories and the
							// precision was 0.00: twenty-four false, eighteen disputed,
							// nothing true. They were login endpoints, OAuth callbacks,
							// invite redemptions and webhooks, plus one lookup whose own
							// source comments that it is deliberately unscoped because
							// the caller was already authorized by signature.
							//
							// Reported, never counted as a finding, never gating -- the
							// same treatment as a flow that cannot be tied to the
							// enumerated surface. Frameworks that expose identity on a
							// request object are untouched, because there the absence of
							// an identity parameter says nothing at all.
							if f.EntryHasNoInjectedIdentity {
								e.unjudgedIdentity = append(e.unjudgedIdentity, f)
								continue
							}
							out = append(out, f)
						}
					}
				}
			}
		}
	}
	sortFindings(out)
	return out
}

// operationCarries reports whether the operation itself was handed data of the other
// class — in any argument or as its receiver.
func (e *engine) operationCarries(c *ir.Call, other *engine) bool {
	if other == nil {
		return false
	}
	if c.ReceiverID != "" && other.tainted[c.ReceiverID] {
		return true
	}
	for _, a := range c.Args {
		if a.ValueID != "" && other.tainted[a.ValueID] {
			return true
		}
	}
	return false
}

// effectivelyRelated reports whether a function relates data of another class to the
// operation in a way that actually governs it.
//
// A comparison counts only when it is a GUARD: a branch from which control can leave
// the handler early. `if (owner !== caller) { res.status(403); return; }` decides
// whether the handler continues; `if (owner !== caller) { log(); }` decides nothing,
// and the two are indistinguishable by position alone.
//
// A call carrying the other class is accepted without that test: an assertion helper
// enforces by throwing, which is a different shape. That is a known looseness — a
// helper that merely records is treated as enforcing.
func effectivelyRelated(chain []*ir.Function, op *ir.Call, other *engine) bool {
	if other == nil || len(chain) == 0 {
		return false
	}

	// The two clauses have different soundness, so they get different scope.
	//
	// A comparison guard may live anywhere on the path: a caller that returns early
	// genuinely prevents the callee from running, so verifying it by control flow is
	// sound across functions.
	//
	// "a call carrying actor identity is presumed to enforce" is only a heuristic —
	// an assertion helper enforces by throwing, but a recorder does not. Spanning the
	// whole call chain with it cleared real defects, so it stays confined to the
	// function performing the operation.
	if sink := chain[0]; sink != nil {
		for _, c := range sink.Calls {
			if c.ID == op.ID {
				continue
			}
			for _, a := range c.Args {
				if a.ValueID != "" && other.tainted[a.ValueID] {
					return true
				}
			}
		}
	}

	for _, fn := range chain {
		var gates []string
		for _, cmp := range fn.Comparisons {
			if cmp.Block == "" {
				continue
			}
			if other.tainted[cmp.Left] || other.tainted[cmp.Right] {
				gates = append(gates, cmp.Block)
			}
		}
		if len(gates) == 0 {
			continue
		}
		if g := cfg.Build(fn); g != nil && g.AnyGuard(gates) {
			return true
		}
	}
	return false
}

// functionsOnPath returns every function this flow actually passed through, derived
// from the evidence chain rather than from the whole call graph. Using the real path
// keeps a guard in one caller from excusing an unguarded call from somewhere else.
func (e *engine) functionsOnPath(valueID string, sink *ir.Function) []*ir.Function {
	seen := map[string]bool{}
	var out []*ir.Function

	add := func(fn *ir.Function) {
		if fn != nil && !seen[fn.ID] {
			seen[fn.ID] = true
			out = append(out, fn)
		}
	}
	add(sink)

	cur := valueID
	for hops := 0; cur != "" && hops < 256; hops++ {
		add(e.ix.OwnerOfValue[cur])
		ed, ok := e.pred[cur]
		if !ok {
			break
		}
		cur = ed.from
	}
	return out
}

// receiverRootParam follows a method call's receiver back through any intermediate
// method calls (`res.status(500).json(x)`) and reports which entry-point parameter it
// originates from, or -1.
func (e *engine) receiverRootParam(c *ir.Call) int {
	return e.rootParamOf(c.ReceiverID, 0)
}

// passedAt returns the value every call site of this function passes at one parameter
// position, or "" when they disagree or there are none.
func (e *engine) passedAt(fn *ir.Function, index, depth int) string {
	if depth >= 3 {
		return ""
	}
	var agreed string
	for _, site := range e.ix.CallSitesOf[fn.ID] {
		var passed string
		for _, a := range site.Args {
			if a.Binds(fn, index) {
				passed = a.ValueID
			}
		}
		if passed == "" {
			return ""
		}
		if agreed == "" {
			agreed = passed
			continue
		}
		// Different values are fine as long as they answer the same question.
		if e.rootParamOf(agreed, depth+1) != e.rootParamOf(passed, depth+1) {
			return ""
		}
	}
	return agreed
}

func (e *engine) rootParamOf(start string, depth int) int {
	id := start
	for hops := 0; hops < 8 && id != ""; hops++ {
		v := e.ix.ValueByID[id]
		if v == nil {
			return -1
		}
		switch v.Kind {
		case ir.ValueParam:
			fn := e.ix.OwnerOfValue[id]
			if fn == nil {
				return -1
			}
			index := -1
			for _, p := range fn.Params {
				if p.ValueID == id {
					index = p.Index
				}
			}
			if index < 0 {
				return -1
			}
			if _, isEntry := e.ix.EntryByFunc[fn.ID]; isEntry {
				return index
			}
			// A parameter of a HELPER. `adminLoginSuccess(redirectPage, session,
			// username, res)` is how a handler that got long gets shorter, and the
			// response object is a value like any other -- but a channel that asks
			// "is this the entry point's second parameter" stopped at the call boundary
			// and answered no, so `res.redirect()` inside the helper was not a response
			// at all. An open redirect in the vulnerable corpus is written exactly that
			// way.
			//
			// Answered from the CALL SITES: whatever they pass at this position is what
			// the parameter is. Agreement is required, so a helper called once from a
			// route and once from a command-line entry says nothing rather than guessing.
			next := e.passedAt(fn, index, depth)
			if next == "" {
				return -1
			}
			id = next
		case ir.ValueCallResult:
			prev := e.callByResult[id]
			if prev == nil {
				return -1
			}
			id = prev.ReceiverID
		default:
			return -1
		}
	}
	return -1
}

// enclosingEntry names the entry point a function belongs to, when it is one.
// injectsIdentity reports whether an entry point was handed the caller's identity as a
// parameter, and whether the program uses that mechanism at all.
//
// The second half is what makes the first half mean anything. On a framework that exposes
// identity on a request object, `req.user` is available whether or not a handler reads it,
// so a handler without it has said nothing. On a framework that INJECTS identity, a
// handler without an identity parameter genuinely was not handed one — the absence is a
// fact about the endpoint rather than about the code that happens to be written in it.
func injectsIdentity(ix *ir.Index, ep *ir.EntryPoint) bool {
	fn := ix.FuncByID[ep.FunctionID]
	if fn == nil {
		return false
	}
	for _, p := range fn.Params {
		if v := ix.ValueByID[p.ValueID]; v != nil && v.Kind == "actor-identity-param" {
			return true
		}
	}
	return false
}

// programInjectsIdentity reports whether ANY entry point in the program is handed the
// caller's identity as a parameter.
func programInjectsIdentity(ix *ir.Index) bool {
	for i := range ix.IR.EntryPoints {
		if injectsIdentity(ix, &ix.IR.EntryPoints[i]) {
			return true
		}
	}
	return false
}

// EntryOf finds the enumerated entry point this function serves, following the call
// graph upward when the function is not itself a handler.
//
// A framework exposes untrusted input in more than one place: a handler parameter, but
// also a request global any helper can read. Requiring the source to sit IN a handler
// would lose the second shape entirely, so reachability is the test — is there an
// enumerated entry point from which this function is called?
// EntryOf is exported because the call-shape analysis asks the same question: a rule
// whose subject is a call rather than a flow still needs to know whether anything a
// caller reaches gets there.
func EntryOf(ix *ir.Index, fn *ir.Function) (*ir.EntryPoint, bool) {
	if ep, ok := ix.EntryByFunc[fn.ID]; ok {
		return ep, true
	}

	seen := map[string]bool{fn.ID: true}
	queue := []string{fn.ID}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		// Called here, or HANDED to something here. Both are ways this function is
		// reached from the function that holds the site, and ReachableFrom has counted
		// both since it existed -- so a walk upward that counted only the first
		// disagreed with the walk downward about which code the surface accounts for.
		for _, site := range append(append([]*ir.Call{}, ix.CallSitesOf[id]...), ix.PassedAt[id]...) {
			caller := ix.OwnerOfCall[site.ID]
			if caller == nil || seen[caller.ID] {
				continue
			}
			seen[caller.ID] = true
			if ep, ok := ix.EntryByFunc[caller.ID]; ok {
				return ep, true
			}
			queue = append(queue, caller.ID)
		}
	}
	return nil, false
}

// enclosingEntry names the entry point a flow belongs to. The second result reports
// whether that name is an ENUMERATED entry point or merely the function the source was
// found in.
//
// The distinction is the whole of ADR-009. A framework model that recognizes a
// parameter decorator but not the routing decorator around it — the two are separate
// detections, and another framework may borrow one vocabulary without the other — will
// happily seed sources in methods that were never enumerated as routes. Those flows may
// be real, but they are not assertions about an attack surface this engine mapped, and
// reporting them as though they were makes the surface look complete when it is not.
func enclosingEntry(ix *ir.Index, fn *ir.Function) (string, bool) {
	if ep, ok := EntryOf(ix, fn); ok {
		return describeEntry(*ep), true
	}
	return fn.Name + "()", false
}

// patternAt returns the regular expression a call uses, written down, or the empty
// string when it was not written down here.
//
// Index -1 is the receiver -- `EMAIL.test(s)` -- which is usually a name bound to a
// literal somewhere above, so plain assignments are followed back. A pattern computed at
// runtime is not written down and is not guessed at: the rule it feeds says something
// definite about a specific pattern, and half a pattern is nothing at all.
func (e *engine) patternAt(c *ir.Call, index int) string {
	var id string
	if index < 0 {
		id = c.ReceiverID
	} else {
		if lit, ok := c.ArgLiterals[index]; ok {
			return lit
		}
		for _, a := range c.Args {
			if a.At(index) {
				id = a.ValueID
			}
		}
	}
	seen := map[string]bool{}
	for hops := 0; hops < 24 && id != "" && !seen[id]; hops++ {
		seen[id] = true
		if v := e.ix.ValueByID[id]; v != nil && v.Kind == ir.ValueLiteral {
			return v.Literal
		}
		// Through a compile step. `PATTERN = re.compile(r"...")` at module scope and
		// `PATTERN.match(s)` in a handler is the normal way to write this in Python, and
		// stopping at the call would mean the rule only ever saw the inline form.
		if c := e.callByResult[id]; c != nil && compilesPattern(c.Callee.Symbol) {
			if lit, ok := c.ArgLiterals[0]; ok {
				return lit
			}
			for _, a := range c.Args {
				if a.At(0) {
					id = a.ValueID
				}
			}
			continue
		}
		id = e.assignedFrom[id]
	}
	return ""
}

func compilesPattern(symbol string) bool {
	switch symbol {
	case "re.compile", "RegExp", "regexp.compile":
		return true
	}
	return false
}

// taintLeads reports whether the caller's value is the FIRST thing composed into this one.
//
// The flows into a composition are recorded in source order -- left before right, head
// before spans -- so the first one is what the finished string starts with. If that is the
// caller's, the program wrote nothing in front of it, and for a destination that means the
// program named no destination at all.
//
// Plain assignments are followed through first, because the composed value is usually
// given a name before it is used.
func (e *engine) taintLeads(valueID string) bool {
	id := valueID
	for hops := 0; hops < 8 && id != ""; hops++ {
		into := e.flowsInto[id]
		switch {
		case len(into) > 1:
			return e.tainted[into[0]]
		case len(into) == 1 && e.assignedFrom[id] == into[0]:
			// The composed value under another name.
			id = into[0]
		case len(into) == 1:
			// A composition with ONE component: `fetch(`${req.query.url}`)` is a template
			// whose head is empty, so nothing is written before the caller's value and
			// nothing was recorded for it either. Requiring two components read that as
			// "not a composition at all" and dropped a finding where the caller supplies
			// the entire destination.
			return e.tainted[into[0]]
		default:
			return false
		}
	}
	return false
}

// composedFrom reports whether any LITERAL piece the sink value was built from contains
// one of these words.
//
// Walks the flows backwards from the sink argument, which is the only direction that
// answers the question: the evidence path follows one witness from the source, and the
// literal halves of a concatenation are not on it. `"SELECT * FROM t WHERE id = " + id`
// puts the verb on a sibling edge, not on the path the taint took.
//
// Bounded, because a value in a large program is reachable from a great many others and
// this runs once per candidate finding.
func (e *engine) composedFrom(valueID string, words []string) bool {
	seen := map[string]bool{}
	frontier := []string{valueID}
	for depth := 0; depth < 12 && len(frontier) > 0; depth++ {
		var next []string
		for _, id := range frontier {
			if seen[id] {
				continue
			}
			seen[id] = true
			if v := e.ix.ValueByID[id]; v != nil && v.Kind == ir.ValueLiteral {
				lower := strings.ToLower(v.Literal)
				for _, w := range words {
					if strings.Contains(lower, w) {
						return true
					}
				}
			}
			next = append(next, e.flowsInto[id]...)
			// Across the call boundary, because a program that builds its statements in a
			// helper is a program that builds them well. `em.query(addColumnQuery(...))`
			// composes the SQL one function away, and a walk that stopped at the call
			// would answer "no verb here" for every statement written that way.
			if c := e.callByResult[id]; c != nil && c.Callee.FunctionID != "" {
				next = append(next, e.returns[c.Callee.FunctionID]...)
			}
		}
		frontier = next
	}
	return false
}

// buildFinding reconstructs the evidence path and decides whether the flow survives
// the sanitizers it actually passed through. Reported=false means taint was cleared.
func (e *engine) buildFinding(c *ir.Call, ch model.Channel, p model.Policy, arg ir.Arg) (Finding, bool) {
	path, origin := e.tracePath(arg.ValueID)
	if ch.Context == "html" && responseBodyMethod(c.Method) && !e.responseBodyIsMarkup(c, arg.ValueID, path) {
		return Finding{}, false
	}
	if e.anchoredRegexGuardClears(c, arg.ValueID, ch.Context) {
		return Finding{}, false
	}

	var sanitizers []Sanitizer
	for _, h := range path {
		if h.Symbol == "" {
			continue
		}
		s, ok := e.m.SanitizerFor(h.Symbol)
		if !ok || !s.AppliesTo(e.class.Class) {
			continue
		}
		// A rule that depends on how the call was written is decided here, where the
		// call's own literals are in hand.
		if s.RequiresLiteralArg != nil {
			if _, written := h.Literals[*s.RequiresLiteralArg]; !written {
				continue
			}
		}
		if s.RequiresInputArg != nil && (!h.HasInputArg || h.InputArg != *s.RequiresInputArg) {
			continue
		}
		clears := s.Clears(ch.Context)
		sanitizers = append(sanitizers, Sanitizer{
			Symbol:   s.Symbol,
			Loc:      h.Loc,
			Clears:   clears,
			Note:     s.Note,
			Required: ch.Context,
		})
		if clears {
			return Finding{}, false
		}
	}

	sinkHop := Hop{
		Loc:         c.Loc,
		Description: fmt.Sprintf("reaches %s() argument %d", sinkName(c), arg.Index),
		Resolution:  c.Callee.Resolution,
	}
	path = append(path, sinkHop)

	// The channel names the weakness when the DESTINATION is what decides it -- untrusted
	// input is CWE-89 at a database and CWE-79 in markup -- and the policy names it when
	// the CLASS is (ADR-012). Failure detail leaving the system is the same weakness
	// whether the page escaped it or not.
	cwe := p.CWE
	if ch.CWE != "" && !p.ClassNamesTheWeakness {
		cwe = ch.CWE
	}

	// A statement-building channel requires the untrusted value to have been BUILT into
	// a statement: concatenated, or interpolated into a template. Passing a value along
	// whole is passing data, not composing a program.
	//
	// This is what separates SQL injection from the method name it shares with everything
	// else. `execute` is a database call on a cursor and a use-case invocation in a CQRS
	// application, and no amount of looking at the name will tell them apart: one
	// production codebase produced 495 findings on `usecase.execute(command)` alone. The
	// command is an object that was constructed, never text that was composed, so the
	// question "was this built into a statement" answers it and the question "what is
	// this method called" never could.
	//
	// The cost is stated rather than hidden: a handler that passes an entire caller-
	// supplied string as the whole query is not composition and is not reported here.
	// The judgement may ask for composition the channel does not.
	if p.RequiresComposition && !composedIntoSinkArgument(path) {
		return Finding{}, false
	}
	if len(ch.ComposedContains) > 0 && !e.composedFrom(arg.ValueID, ch.ComposedContains) {
		return Finding{}, false
	}
	if ch.RequiresComposition && !composedIntoSinkArgument(path) {
		return Finding{}, false
	}
	// A destination is chosen, not built. Untrusted data composed into it usually leaves
	// the caller a path segment rather than a machine to point at.
	if ch.RequiresWholeValue && composedIntoText(path) &&
		!(ch.AllowsComposedPrefix && e.taintLeads(arg.ValueID)) {
		return Finding{}, false
	}

	// A value that became a FIELD of something is not the caller's object being handed
	// over whole. `update({ name: req.body.name })` names the field it writes.
	if ch.RequiresUnenclosed && enclosed(path) {
		return Finding{}, false
	}
	// A process argument is dangerous because it became one member of argv, not merely
	// because a list-shaped value reached Popen. This also leaves shell interpretation
	// on its existing composition rule: one flow cannot satisfy both shapes by accident.
	if ch.RequiresEnclosure && !argvEnclosed(path) {
		return Finding{}, false
	}
	if ch.Context == "argv" && e.argvProtected(arg.ValueID) {
		return Finding{}, false
	}

	// And a value READ OUT of a structure is not the structure. One environment variable
	// published on purpose is not the environment.
	if p.RequiresUnprojected && projected(path) {
		return Finding{}, false
	}

	// A channel that needs to know what its receiver is, matched by a frontend that
	// could not say, is a weaker claim than the path resolution alone suggests. It is
	// still reported — the operation may well be a record selector — but it has not
	// earned the confidence that stops a build (ADR-005).
	confidence := confidenceOf(path)
	// No type at all is the unanswerable case -- and so is an ANONYMOUS one. A receiver
	// typed `__object` is an object literal, which is what an aggregating namespace looks
	// like: budibase reaches its data layer through `sdk.queries`, an object built out of
	// other modules, and that says no more about whether records live behind it than no
	// type at all does. An origin that is merely empty means "not a builtin", which is
	// what every ORM in existence looks like, so that is not the test.
	if ch.RequiresExternalReceiver && (c.ReceiverType == "" || c.ReceiverType == "__object") && confidence == High {
		confidence = Medium
	}

	sd := e.seeds[origin]
	return Finding{
		Analysis:   p.ID,
		DataClass:  e.class.Class,
		ChannelID:  ch.ID,
		Visibility: ch.Visibility,
		Class:      p.Finding,
		CWE:        cwe,
		Message:    p.Reason,
		// The ADJUSTED confidence, not a second call to confidenceOf. This read
		// `confidenceOf(path)` and silently discarded the demotion computed four lines
		// above, so a channel that needs to know what its receiver is and did not get an
		// answer still reached the tier that stops a build. It surfaced on budibase,
		// whose `sdk.navigation.update()` is an application module rather than a store of
		// shared records, and which gated at high confidence on exactly the evidence the
		// demotion exists to discount.
		Confidence:    confidence,
		SourceLoc:     e.locOf(origin),
		SourceLabel:   sd.label,
		EntryPoint:    sd.entryPoint,
		EntryMethod:   sd.method,
		EntryPath:     sd.path,
		EntryAnchored: sd.anchored,
		EntryTrust:    sd.trust,
		EntryHasNoInjectedIdentity: sd.anchored && !sd.identityInjected && e.programInjects &&
			p.RequiresRelationTo == e.m.IdentityClass(),
		SinkLoc: c.Loc,
		// Every other analysis has marked this since the field existed; the dataflow
		// analysis never did, and it is the one that produces most of the findings. So
		// the whole test-module judgement -- reported, never gating, published at note
		// rather than error -- silently did not apply to taint at all. It surfaced as a
		// CWE-639 in `pat.e2e.test.ts` arriving at warning next to real ones.
		InTestModule: e.ix.InTestModule(c.Loc),
		SinkSymbol:   sinkName(c),
		SinkArgIndex: arg.Index,
		SinkContext:  ch.Context,
		SinkRational: ch.Rationale,
		Path:         path,
		Sanitizers:   sanitizers,
	}, true
}

func responseBodyMethod(method string) bool {
	switch strings.ToLower(method) {
	case "send", "write", "end":
		return true
	default:
		return false
	}
}

// responseBodyIsMarkup decides the precondition of an HTML channel from facts about
// this response, not from the spelling `send`. Fastify serializes objects as JSON; a
// dominating Content-Type or execution-blocking response header says what a string is;
// and none of those facts changes the separate public-visibility channel.
func (e *engine) responseBodyIsMarkup(sink *ir.Call, valueID string, path []Hop) bool {
	contentType, blocked := e.dominatingResponseFacts(sink)
	if blocked {
		return false
	}
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml") {
		return true
	}
	if contentType != "" {
		return false
	}
	// An object or array is a serialization input, not response bytes. Only the sink
	// argument's own shape counts: a string renderer may have consumed an object several
	// calls earlier, and an enclosure anywhere on the taint path would misclassify its
	// eventual SVG/RSS output as JSON.
	if e.valueIsEnclosure(valueID) {
		return false
	}
	for _, h := range path {
		name := strings.ToLower(h.Symbol)
		if name == "json.stringify" || name == "json.dumps" {
			return false
		}
	}
	return true
}

func (e *engine) valueIsEnclosure(id string) bool {
	for hops := 0; hops < 8 && id != ""; hops++ {
		into := e.flowEdgesInto[id]
		for _, f := range into {
			if f.Kind == "enclose" {
				return true
			}
		}
		if len(into) != 1 || into[0].Kind != "assign" {
			return false
		}
		id = into[0].From
	}
	return false
}

func (e *engine) dominatingResponseFacts(sink *ir.Call) (contentType string, blocked bool) {
	fn := e.ix.OwnerOfCall[sink.ID]
	if fn == nil || sink.Block == "" {
		return "", false
	}
	g := cfg.Build(fn)
	if g == nil {
		return "", false
	}
	root := e.responseReceiverRoot(sink.ReceiverID)
	if root == "" {
		return "", false
	}
	for _, c := range fn.Calls {
		if c.ID == sink.ID || e.responseReceiverRoot(c.ReceiverID) != root ||
			!callDominates(c, sink, g) {
			continue
		}
		name, value, ok := responseHeader(c)
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.ToLower(strings.TrimSpace(value))
		switch name {
		case "content-type":
			contentType = value
		case "content-security-policy":
			if strings.Contains(value, "sandbox") && !strings.Contains(value, "allow-scripts") {
				blocked = true
			}
		case "content-disposition":
			if strings.Contains(value, "attachment") {
				blocked = true
			}
		}
	}
	return contentType, blocked
}

func callDominates(before, after *ir.Call, g *cfg.Graph) bool {
	if before.Block == "" || after.Block == "" || !g.Dominates(before.Block, after.Block) {
		return false
	}
	if before.Block != after.Block {
		return true
	}
	if before.Loc.Line != after.Loc.Line {
		return before.Loc.Line < after.Loc.Line
	}
	return before.Loc.Column < after.Loc.Column
}

func responseHeader(c *ir.Call) (name, value string, ok bool) {
	switch strings.ToLower(c.Method) {
	case "setheader", "header":
		name, nok := c.ArgLiterals[0]
		value, vok := c.ArgLiterals[1]
		return name, value, nok && vok
	case "type":
		value, ok := c.ArgLiterals[0]
		return "content-type", value, ok
	case "set", "headers":
		for i, literal := range c.ArgLiterals {
			if i >= 0 {
				continue
			}
			if key, val, cut := strings.Cut(literal, "="); cut {
				lower := strings.ToLower(strings.TrimSpace(key))
				if lower == "content-type" || lower == "content-security-policy" || lower == "content-disposition" {
					return key, val, true
				}
			}
		}
	}
	return "", "", false
}

func (e *engine) responseReceiverRoot(id string) string {
	for hops := 0; hops < 12 && id != ""; hops++ {
		if from := e.assignedFrom[id]; from != "" {
			id = from
			continue
		}
		made := e.callByResult[id]
		if made == nil || made.ReceiverID == "" {
			return id
		}
		id = made.ReceiverID
	}
	return id
}

// anchoredRegexGuardClears credits a full-string allow-list only when the graph and the
// pattern prove complementary facts: regex FAILURE is the branch that leaves, success is
// the only branch that reaches this sink, and the accepted language cannot spell the
// syntax this sink interprets.
//
// Measured case: misskey had two path-traversal findings where `path.match(
// /^[0-9a-f-]+\.png$/)` (and the svg equivalent) returned 404 on failure before
// sendFile. The dot is safe because it can occur only once; matching known pattern text
// would miss that judgement and would make the next allow-list silently unsafe.
func (e *engine) anchoredRegexGuardClears(sink *ir.Call, valueID, context string) bool {
	// A syntax allow-list changes what caller input can DO at a particular sink. It does
	// not make a password non-secret or a clock-derived token unpredictable.
	if e.class.Class != "untrusted-input" || sink.Block == "" {
		return false
	}
	forbidden := regexGuardForbidden(context)
	if len(forbidden) == 0 {
		return false
	}
	fn := e.ix.OwnerOfCall[sink.ID]
	if fn == nil {
		return false
	}
	g := cfg.Build(fn)
	if g == nil {
		return false
	}
	for _, check := range fn.Calls {
		if check.Block == "" || check.ConditionBranch != "falsy" || !g.IsGuard(check.Block) ||
			!g.Dominates(check.Block, sink.Block) || !g.SelectedBySuccessor(sink.Block, check.Block, 1) {
			continue
		}
		input, pattern, ok := regexGuardOperands(e.ix, check)
		if !ok || input != valueID {
			continue
		}
		if model.AnchoredRegexExcludes(pattern, forbidden...) {
			return true
		}
	}
	return false
}

func regexGuardOperands(ix *ir.Index, c *ir.Call) (input, pattern string, ok bool) {
	switch c.Method {
	case "match":
		pattern, ok = c.ArgLiterals[0]
		return c.ReceiverID, pattern, ok && c.ReceiverID != ""
	case "test":
		v := ix.ValueByID[c.ReceiverID]
		a, written := argAt(c, 0)
		if written {
			input = a.ValueID
		}
		if v == nil || v.Kind != ir.ValueLiteral || input == "" {
			return "", "", false
		}
		return input, v.Literal, true
	default:
		return "", "", false
	}
}

func regexGuardForbidden(context string) []string {
	switch context {
	case "path":
		return []string{"/", `\`, ".."}
	case "html":
		return []string{"<", ">", "&", `"`}
	case "header", "log-line":
		return []string{"\r", "\n"}
	default:
		return nil
	}
}

// originOf returns the seed a tainted value came from.
func (e *engine) originOf(id string) string {
	seen := map[string]bool{}
	for id != "" && !seen[id] {
		seen[id] = true
		if _, ok := e.seeds[id]; ok {
			return id
		}
		id = e.pred[id].from
	}
	return ""
}

// tracePath walks predecessors back to the seed and returns the path in source order.
func (e *engine) tracePath(valueID string) ([]Hop, string) {
	var reversed []Hop
	cur := valueID
	origin := valueID
	seen := make(map[string]bool)

	for cur != "" && !seen[cur] {
		seen[cur] = true
		ed, ok := e.pred[cur]
		if !ok {
			break
		}
		reversed = append(reversed, Hop{
			Loc:         ed.loc,
			Description: ed.desc,
			Symbol:      ed.symbol,
			Literals:    ed.literals,
			InputArg:    ed.inputArg,
			HasInputArg: ed.hasInputArg,
			Kind:        ed.kind,
			Resolution:  ed.resolution,
		})
		origin = cur
		cur = ed.from
	}

	path := make([]Hop, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		path = append(path, reversed[i])
	}
	return path, origin
}

// markTainted records that a value carries the class, and WHICH path is kept as the
// witness for it.
//
// A value is often reached more than once -- `cond ? Number(id) : trunc(id)` merges two
// paths into one -- and only the first edge was ever kept. That is wrong whenever the two
// differ in what they passed through: the sink drops a finding when its path traverses a
// transform that clears the context, so a SANITIZED branch arriving first silenced an
// unsanitized one arriving second. Juice Shop's `$where` injection is written exactly that
// way, and it read as clean.
//
// So a path that passed through no transform at all displaces one that did. It is the
// stronger witness for the same fact, and nothing about the value's taint changes -- only
// the evidence offered for it, which is what the sink then judges (ADR-006). The
// replacement can happen at most once per value, because it only ever goes from "went
// through something" to "did not".
func (e *engine) markTainted(id string, ed edge) {
	if id == "" {
		return
	}
	via := e.viaTransform[ed.from] || e.isTransform(ed.symbol)
	if e.tainted[id] {
		if !e.viaTransform[id] || via {
			return
		}
		e.pred[id] = ed
		e.viaTransform[id] = false
		e.queue = append(e.queue, id)
		return
	}
	e.tainted[id] = true
	e.pred[id] = ed
	e.viaTransform[id] = via
	e.queue = append(e.queue, id)
}

// carriesRecord passes a record handle along a hop that only RENAMES it -- an assignment,
// a return, a parameter binding. The row is the same row under another name, and nothing
// has been read out of it yet.
func (e *engine) carriesRecord(from, to string) {
	if fields := e.recordFields[from]; len(fields) > 0 && !e.hasRecord(to) {
		e.recordFields[to] = fields
	}
}

func (e *engine) hasRecord(id string) bool { return len(e.recordFields[id]) > 0 }

// isTransform reports whether a symbol is one the model has anything to say about as a
// sanitizer. Deliberately not "does it clear this context" -- the context belongs to the
// sink and is not known here, and a path through no transform is the better witness
// whatever the sink turns out to be.
func (e *engine) isTransform(symbol string) bool {
	if symbol == "" {
		return false
	}
	_, ok := e.m.SanitizerFor(symbol)
	return ok
}

func (e *engine) describeFlow(f ir.Flow) string {
	target := e.ix.ValueByID[f.To]
	name := ""
	if target != nil {
		name = target.Name
	}
	switch f.Kind {
	case "assign":
		if name != "" {
			return fmt.Sprintf("assigned to `%s`", name)
		}
		return "assigned"
	case "template":
		return "interpolated into a template literal"
	case "binary":
		return "concatenated"
	case "property":
		if target != nil && target.Path != "" {
			return fmt.Sprintf("property `%s`", target.Path)
		}
		return "property access"
	case "return":
		return "returned"
	default:
		return f.Kind
	}
}

func (e *engine) locOf(valueID string) ir.Loc {
	if v := e.ix.ValueByID[valueID]; v != nil {
		return v.Loc
	}
	return ir.Loc{}
}

func confidenceOf(path []Hop) Confidence {
	worst := High
	for _, h := range path {
		switch h.Resolution {
		case ir.DynamicUnresolved:
			return Low
		case ir.Probable:
			worst = Medium
		}
	}
	return worst
}

func sinkFunctionName(ix *ir.Index, c *ir.Call) string {
	if fn := ix.OwnerOfCall[c.ID]; fn != nil {
		return fn.Name
	}
	return ""
}

// Touches reports whether any file this finding depends on is in the given set.
//
// The whole evidence path counts, not just the sink. A change to a helper can introduce
// a defect whose dangerous operation sits in a file the change never opened, and scoping
// to the sink alone would hide exactly the flows that a review most needs to see: the
// ones where the damage happens somewhere the author was not looking.
func (f Finding) Touches(files map[string]bool) bool {
	if files[f.SinkLoc.File] || files[f.SourceLoc.File] {
		return true
	}
	for _, h := range f.Path {
		if files[h.Loc.File] {
			return true
		}
	}
	for _, site := range f.RelatedSites {
		if files[site.Loc.File] {
			return true
		}
		for _, h := range site.Path {
			if files[h.Loc.File] {
				return true
			}
		}
	}
	return false
}

// Fingerprint is a finding's identity across runs.
//
// Deliberately built from what the finding IS and not from where it currently sits: the
// judgement, the entry point it belongs to, the file and function holding the operation,
// the symbol reached, and what the data was. A line number is absent on purpose —
// inserting an import above a defect must not turn it into a new defect, or a baseline
// is worthless on the first commit that touches the file.
//
// Two genuinely indistinguishable findings share a fingerprint. That is correct: for the
// question a baseline asks — is this one already known — they are the same finding.
//
// Discriminator is appended only when a rule HAS one, which is what keeps every
// fingerprint ever recorded against a rule that does not. The ledger holds hand
// adjudications keyed by this value; a scheme that re-hashed every finding to fix three
// of them would have thrown the record away to make the record more precise.
func (f Finding) Fingerprint() string {
	parts := []string{
		f.Analysis,
		f.CWE,
		f.EntryPoint,
		f.SinkLoc.File,
		f.SinkFunction,
		f.SinkSymbol,
		f.SourceLabel,
	}
	if f.Discriminator != "" {
		parts = append(parts, f.Discriminator)
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:8])
}

func describeEntry(ep ir.EntryPoint) string {
	parts := make([]string, 0, 3)
	if m := ep.Detail["method"]; m != "" {
		parts = append(parts, m)
	}
	if p := ep.Detail["path"]; p != "" {
		parts = append(parts, p)
	}
	desc := strings.Join(parts, " ")
	// An entry point that is not a route has no method and no path, and its KIND alone
	// makes every one of them read the same. Whichever detail names this particular
	// registration -- the command an operator types, the event a bus delivers, the
	// schedule a timer keeps, the module a process starts in -- is what a reader needs
	// to find it, and it is the only thing distinguishing seventeen sibling jobs.
	if desc == "" {
		for _, key := range []string{"command", "event", "schedule", "trigger", "start"} {
			if v := ep.Detail[key]; v != "" {
				desc = ep.Kind + " " + v
				break
			}
		}
	}
	if desc == "" {
		desc = ep.Kind
	}
	if ep.Framework != "" {
		desc += " [" + ep.Framework + "]"
	}
	return desc
}

// sinkName is how a sink is identified in output: its resolved symbol when there is
// one, otherwise the method it was reached through.
func sinkName(c *ir.Call) string {
	if c.Callee.Symbol != "" {
		return c.Callee.Symbol
	}
	if c.Method != "" {
		return "." + c.Method
	}
	return "<unresolved>"
}

func displaySymbol(c ir.Callee) string {
	if c.Symbol != "" {
		return c.Symbol
	}
	return "<unresolved call>"
}

func matchesPath(path string, prefixes []string) bool {
	head, _, _ := strings.Cut(path, ".")
	for _, p := range prefixes {
		if head == p {
			return true
		}
	}
	return false
}

func paramAt(fn *ir.Function, index int) (ir.Param, bool) {
	for _, p := range fn.Params {
		if p.Index == index {
			return p, true
		}
	}
	return ir.Param{}, false
}

func argAt(c *ir.Call, index int) (ir.Arg, bool) {
	for _, a := range c.Args {
		if a.At(index) {
			return a, true
		}
	}
	return ir.Arg{}, false
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
