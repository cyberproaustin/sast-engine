// Package ir defines the Program IR: the ONLY contract between language frontends
// and the core (docs/DESIGN-DECISIONS.md ADR-001). A frontend lowers a codebase into
// this shape and stops; the core consumes this shape and produces every finding.
//
// Nothing in this package may reference a language, parser, or framework. If an
// analysis needs a fact that is not here, the fix is to add the fact to the IR —
// where every frontend can supply it — not to reach across the seam.
package ir

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// SupportedMajor is the IR major version this core implements.
const SupportedMajor = 0

// IR is a lowered program.
type IR struct {
	IRVersion   string       `json:"irVersion"`
	Frontend    Frontend     `json:"frontend"`
	Modules     []Module     `json:"modules"`
	Functions   []*Function  `json:"functions"`
	EntryPoints []EntryPoint `json:"entryPoints"`

	// DeclaredViews are the request handlers the application never wrote.
	//
	// A Django REST Framework view is a class holding four assignments. The framework
	// reads them, resolves one record out of the URL, runs the permission classes and
	// answers; there is no handler body, no gate call and no operation call, so every
	// judgement in this engine that relates one call to another has nothing to look at.
	// Seven confirmed cross-project IDORs walked past an analysis written for exactly
	// that relation because both of its operands were class attributes.
	//
	// A separate fact rather than more Detail on an entry point, and for the reason
	// Views and Renders are separate: an entry point is a FUNCTION the surface reached,
	// and these views have no function at all. Attaching them to one would have meant
	// inventing it.
	DeclaredViews []DeclaredView `json:"declaredViews,omitempty"`

	// Views are the application's templates, and Renders are the sites that hand a
	// context to one. They are TWO facts rather than one because they are two facts:
	// the file that decides the escaping and the call that supplies the value are
	// routinely not in the same function, not in the same module, and never in the same
	// language. A frontend that joined them itself could only join the ones written
	// together, which is a shape real applications do not have.
	Views   []View   `json:"views,omitempty"`
	Renders []Render `json:"renders,omitempty"`

	// ViewsJoined records that the core has already written this document's template
	// sinks into it. Deliberately not serialized: it is a fact about this process's copy
	// of the program, and a scan run twice over one document would otherwise report
	// every interpolation twice.
	ViewsJoined bool `json:"-"`
}

// DeclaredView is one registered view class and the four things it declared about how the
// framework should serve it.
//
// Deliberately says nothing about the framework's vocabulary. `lookup_url_kwarg`,
// `get_queryset` and `has_object_permission` are DRF's words for these facts and they
// stay in the frontend that read them; what crosses the IR is which REQUEST KEY each
// declaration was about, because that is the only part a judgement about scope needs and
// the only part the next framework will spell the same way.
type DeclaredView struct {
	// ID is the class as the program identifies it: module and name.
	ID        string `json:"id"`
	Framework string `json:"framework,omitempty"`
	// Name is the class name, which is what a reader recognises in a stack trace.
	Name string `json:"name"`
	Loc  Loc    `json:"loc"`
	// Handlers are the view's own methods that answer a request, so a judgement about
	// the declared authorization can reach the bodies it governs.
	Handlers []string `json:"handlers,omitempty"`
	// Authorizes are the request keys the declared authorization consults. Several,
	// because a view composes permission classes and each may ask about a different key;
	// the scope the view was authorized against is their union.
	Authorizes []DeclaredKey `json:"authorizes,omitempty"`
	// Selects is the request key the framework resolves the record from, when the class
	// declared one. Absent means the view answers about a collection rather than a row.
	Selects *DeclaredKey `json:"selects,omitempty"`
	// Constrains are the request keys the application's own query override narrows by.
	// This is where a correctly scoped view states its relation, and its absence is the
	// finding.
	Constrains []DeclaredKey `json:"constrains,omitempty"`
	// Resolves are the view's own accessors that stand for a request key. `By` is the
	// accessor's name.
	//
	// `self.project.examples` in a handler body is a query already narrowed to the
	// authorized project, and nothing in the body says so -- `project` is a property
	// elsewhere in the class that fetches the row `self.kwargs["project_id"]` names.
	// Without this the same line reads as an unconstrained query over every row.
	Resolves []DeclaredKey `json:"resolves,omitempty"`
	// ObjectRelation names the declaration that ties the SELECTED record to the caller,
	// when the application made one. A framework that offers a hook for object-level
	// authorization and an application that uses it have settled this question between
	// them, whatever the URL keys say.
	ObjectRelation string `json:"objectRelation,omitempty"`
	// Target is the query the class declared, which is the operation the framework
	// performs with the selected key.
	Target *DeclaredTarget `json:"target,omitempty"`
}

// DeclaredKey is one request key a declaration was about, and which declaration that was.
type DeclaredKey struct {
	Key string `json:"key"`
	// By is the declaration that consults it -- the attribute, the override, or the
	// permission class -- so a finding can cite the line that made the claim.
	By  string `json:"by"`
	Loc Loc    `json:"loc"`
}

// DeclaredTarget is the store query a view declared, named as the application wrote it.
type DeclaredTarget struct {
	Symbol string `json:"symbol"`
	Loc    Loc    `json:"loc"`
}

// View is one template: what it writes into the page, and which other templates it
// draws into itself.
type View struct {
	// ID is the view's root-relative path, which is also how a render names it.
	ID string `json:"id"`
	// Extends are the views this one fills in. Rendering this view renders each of
	// them, with THIS view's context.
	Extends []string `json:"extends,omitempty"`
	// Includes are the views this one draws in, likewise with its own context.
	Includes []Include  `json:"includes,omitempty"`
	Reads    []ViewRead `json:"reads,omitempty"`
}

// Include is one view drawn into another, and what the caller's names are called
// inside it.
type Include struct {
	View string `json:"view"`
	// Rebind maps a name that is FREE in the included view to the path it stands for
	// in the including one. A view included from inside a loop reads the loop's
	// variable, and that variable is an element of something the render call passed:
	// `{% for infobox in infoboxes %}{% include 'infobox.html' %}` makes the included
	// file's `infobox` a read of `infoboxes`.
	Rebind map[string]string `json:"rebind,omitempty"`
}

// ViewRead is one value written into a page.
type ViewRead struct {
	// Path is the access path read, rooted at a name the context supplies.
	Path string `json:"path"`
	// Escaped is whether the engine escapes this one for markup.
	Escaped bool `json:"escaped"`
	// Context is the syntax the value lands IN, when it is not ordinary markup.
	// "script" means inside a `<script>` element, where the HTML parser ends the
	// element at the first `</script` whatever the JavaScript around it says — so a
	// value escaped for a JavaScript string is still unescaped for the place it landed.
	Context string `json:"context,omitempty"`
	// RemovedAt is where the marker that turned the engine's escaping OFF is written.
	//
	// An absent encoder and a REMOVED one are different facts about a line, and only the
	// second has something a reader can go and look at. Autoescaping is on in both
	// template languages this engine reads, so an unescaped interpolation is always
	// somebody's decision; this is where they wrote it down.
	RemovedAt *Loc `json:"removedAt,omitempty"`
	Loc       Loc  `json:"loc"`
}

// Render is one site that hands a context to a view.
type Render struct {
	// View is the resolved view id, when the name was written at this call.
	View string `json:"view,omitempty"`
	// Name is the view name as written, for evidence.
	Name string `json:"name,omitempty"`
	// FromParam names the enclosing function's parameter that supplies the view name,
	// for a render whose caller chooses the view. A framework's base handler is written
	// exactly this way: one method that takes the name, adds the application-wide
	// namespace, and renders.
	FromParam string `json:"fromParam,omitempty"`
	// ForwardsKeywords says this render hands on the enclosing function's own keyword
	// arguments, so the names bound at ITS call sites are bound in the view.
	ForwardsKeywords bool `json:"forwardsKeywords,omitempty"`

	// ContextValues are mappings this render hands over WHOLE instead of naming each
	// variable: `render_template(name, **ns)`, and the positional context object that
	// Django and Express both take, where a context is one object and never a keyword
	// list.
	//
	// The names a view then reads are that mapping's KEYS, and a mapping is routinely
	// filled in somewhere other than the call — a base handler mutates it, a helper
	// returns it, a loop writes into it. A frontend states only which value was handed
	// over; which names it carries is a program-wide question the core answers, because
	// the answer is not in this function (docs/DESIGN-DECISIONS.md ADR-001).
	ContextValues []string `json:"contextValues,omitempty"`

	FunctionID string    `json:"functionId"`
	Loc        Loc       `json:"loc"`
	Block      string    `json:"block,omitempty"`
	Bindings   []Binding `json:"bindings,omitempty"`
}

// Binding is one name a render gives the view, and the value behind it.
type Binding struct {
	Name    string `json:"name"`
	ValueID string `json:"valueId"`
}

// Frontend identifies the producer and declares what it can support.
type Frontend struct {
	Name         string       `json:"name"`
	Version      string       `json:"version"`
	Capabilities Capabilities `json:"capabilities"`
}

// Capabilities is the honesty mechanism (ADR-003). An analysis whose requirements are
// not met is reported NOT APPLICABLE, never as a clean result.
type Capabilities struct {
	TypeChecker     bool `json:"typeChecker"`
	Interprocedural bool `json:"interprocedural"`
	CrossModule     bool `json:"crossModule"`
	ControlFlow     bool `json:"controlFlow"`
	// Templates says the frontend read the application's VIEWS as well as its source.
	//
	// A server-rendered application makes every escaping decision in a file the
	// language's own compiler has never heard of. A frontend that reads only the source
	// is not wrong about the handler; it is silent about the half where the decision was
	// made, and an analysis that cannot tell those apart reports a clean view layer it
	// never opened (ADR-003).
	Templates       bool     `json:"templates,omitempty"`
	FrameworkModels []string `json:"frameworkModels"`
}

// Module is one compilation unit.
type Module struct {
	ID   string `json:"id"`
	Path string `json:"path"`
	// IsTest marks a module that ships with the code but does not run in production.
	//
	// What counts as a test file is an ecosystem convention -- `.test.ts`, `_test.go`,
	// `test_*.py`, a `__tests__` directory -- so the frontend decides it, the same way it
	// decides what a builtin type is. The core only decides what it MEANS.
	//
	// It means a finding here does not gate. A key written into a test is in the
	// repository and in its history exactly as the reason says, and it is still not a
	// production credential: 23 of 23 hardcoded-secret findings across sixteen
	// repositories were test fixtures, every one of them gating.
	IsTest bool `json:"isTest,omitempty"`
	// Provenance records why this module is not hand-written application code. The
	// frontend owns the classification because package/workspace conventions and
	// generated-source shapes are language and ecosystem facts; the core owns what the
	// distinction means to a finding and to the enumerated surface.
	Provenance Provenance `json:"provenance,omitempty"`
	// Unreferenced marks a module no other module in the program names -- no import,
	// no re-export, no `require`, no dynamic `import()` -- and that no framework
	// convention loads by path.
	//
	// A graph fact, stated by the frontend because resolving a specifier to a file is a
	// language question, and read by the core because what it MEANS to a finding is not.
	// It means the finding is not standing on the enumerated surface: an application
	// reported a `window.open` inside a settings button as though a caller could reach
	// it, and the component was not imported, re-exported or dynamically loaded anywhere
	// in its own repository. False is no claim either way, which is what every frontend
	// that does not compute this says.
	Unreferenced bool `json:"unreferenced,omitempty"`
}

// Provenance is where a module came from when it is not ordinary first-party source.
type Provenance string

const (
	Vendored  Provenance = "vendored"
	Example   Provenance = "example"
	Generated Provenance = "generated"
	// Tooling is build and development machinery that ships in the repository and does
	// not run in the deployed application: a watch script, a release script, a
	// packaging script.
	//
	// Not a smaller kind of application code. A `setInterval` in a dev-watch script is a
	// recurring callback on a developer's laptop, and counting it in the surface an
	// operator is meant to audit against the application they run is the same category
	// error as counting an example route -- which is the one this file already draws the
	// line for.
	Tooling Provenance = "tooling"
)

// Trust is who can cause an entry point to run.
//
// The surface stopped being all one kind the moment anything but an HTTP route was
// enumerated. A cron job, a management command and a process start are all code that
// runs with the application's privileges, and none of them is an anonymous request:
// saying so is the difference between "a stranger can do this to you" and "whoever
// already has a shell here can". Ranking them together would be a lie in one direction
// or the other, so the frontend states which it is and the core decides what it means —
// the same division Provenance and IsTest already draw.
//
// Deliberately about WHO CAN TRIGGER the code, not about what the code reads. What a
// scheduled job reads is answered by the source rules that seed it, and a job reading a
// store an HTTP request wrote into carries the REQUEST's trust, because that is where
// the value came from.
type Trust string

const (
	// Remote: anything that can reach the service. An HTTP route.
	Remote Trust = "remote"
	// Operator: someone who can already run a command on the host or start the
	// process. A management command's arguments and a process's configuration.
	Operator Trust = "operator"
	// Internal: nothing outside the process triggers it at all. A timer fires it, or
	// an in-process bus delivers to it.
	Internal Trust = "internal"
)

// Loc is a source position. Line and Column are 1-based.
type Loc struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

func (l Loc) String() string { return fmt.Sprintf("%s:%d:%d", l.File, l.Line, l.Column) }

// Function is the unit of intraprocedural dataflow.
type Function struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Module  string   `json:"module"`
	Loc     Loc      `json:"loc"`
	Params  []Param  `json:"params"`
	Values  []*Value `json:"values"`
	Flows   []Flow   `json:"flows"`
	Calls   []*Call  `json:"calls"`
	Returns []string `json:"returns"`
	// ReturnBlocks is where each returned value LEFT the function, index-aligned with
	// Returns.
	//
	// A return had no position in the graph, which made "on what condition does this
	// function answer with the caller's value" unaskable. medplum's `getClientRedirectUri`
	// is the shape: it returns the registered URI, the requested one, or nothing, and the
	// requested one only inside the branch that proved it shares an origin with a
	// registered one. Every other fact needed to see that is already here -- the blocks,
	// the comparisons, the dominance -- and the one missing piece was which block the
	// `return` sat in. `Call` and `Flow` both carry this field for the same reason.
	//
	// A frontend that does not state it emits nothing, and a length that does not match
	// Returns is a REFUSAL rather than a partial answer: the alignment is the only thing
	// joining a value to its position, so a core that cannot trust it must not guess.
	ReturnBlocks []string `json:"returnBlocks,omitempty"`
	EntryBlock   string   `json:"entryBlock,omitempty"`
	Blocks       []Block  `json:"blocks,omitempty"`
	// Comparisons are relational facts: which values were tested against which.
	// Dataflow alone cannot see that a handler checked one thing against another,
	// and "was this related to the caller's identity?" is exactly that question.
	Comparisons []Comparison `json:"comparisons,omitempty"`
	// Writes are assignments INTO something: `session["user"] = x`, `config.debug = y`.
	//
	// Only assignments to a plain name were lowered before, so writing into a property or
	// a subscript recorded nothing at all -- and putting caller data into a session is a
	// weakness whose entire shape is the write.
	//
	// Deliberately not fed into taint propagation. Whether a value read back out of an
	// object should carry what was written into it is a field-sensitivity question this
	// project measured once and found worth nothing, and answering it as a side effect of
	// recording the write would be deciding it by accident.
	Writes []Write `json:"writes,omitempty"`
}

// Write is an assignment into a property or a subscript of something.
type Write struct {
	Loc Loc `json:"loc"`
	// Base is the value being written INTO, when the frontend could identify one.
	Base string `json:"base,omitempty"`
	// Path is what was written to: a property name, or the key of a subscript when it
	// was written as a literal.
	Path string `json:"path,omitempty"`
	// From is the value written, when it produced one.
	From string `json:"from,omitempty"`
	// Key is the value the entry was FILED UNDER, for a subscript whose key was
	// computed rather than written down. `cache[req.params.id] = entry` records the
	// entry in From and the identifier the caller chose in Key, and it is the key that
	// decides how many entries the container can come to hold: one per distinct key.
	//
	// Path already carries a key that was written as a literal, because a literal key is
	// a property name spelled differently and a fixed set of names cannot grow. The two
	// are never both set.
	Key string `json:"key,omitempty"`

	// Block is the basic block this write occurs in, and it exists for the same reason
	// the flows carry one: a question about what a CHECK settled before the write
	// cannot be answered from a line number. Two writes on the same line of two
	// programs sit in different places in the graph, and only one of them is downstream
	// of a rejection.
	//
	// Absent is a refusal, never a default. Switch arms have no graph position; loop-body
	// writes retain the same refusal until narrowing the analyses that consume this field
	// has been measured separately from emitting the repetition itself.
	Block string `json:"block,omitempty"`

	// Scope says how far the destination reaches, for a write whose danger is not what
	// it writes into but how long that lives. "process" marks state shared by every
	// request this process handles.
	//
	// The frontend decides it, because what makes an assignment reach outside the
	// function is a language rule: Python needs the name declared global and JavaScript
	// needs it bound in an enclosing scope, and the same statement without either touches
	// nothing but a local.
	Scope string `json:"scope,omitempty"`
}

// Comparison is one relational test between two values.
type Comparison struct {
	Left  string `json:"left"`
	Right string `json:"right"`
	Op    string `json:"op"`
	Block string `json:"block,omitempty"`
	Loc   Loc    `json:"loc"`
}

// Block is a basic block: straight-line code with a single entry. Terminator says how
// control leaves it — "branch" when the block ends in a test, "return"/"throw" when it
// leaves the function. A block with no successors is an exit.
type Block struct {
	ID         string   `json:"id"`
	Successors []string `json:"successors,omitempty"`
	Terminator string   `json:"terminator,omitempty"`
	Loc        Loc      `json:"loc"`

	// LoopHeader marks the entry to a repetition. The back edge is not duplicated in
	// another vocabulary: it is the ordinary successor from the repeating region back
	// to this block, so every graph algorithm sees the same edge.
	LoopHeader bool `json:"loopHeader,omitempty"`
	// LoopBound is the value whose extent or truth decides whether the loop repeats.
	// Empty means the language construct wrote no such expression, as in `for (;;)`,
	// and is a refusal rather than a claim that the repetition is unbounded.
	LoopBound string `json:"loopBound,omitempty"`
}

// Param is a formal parameter bound to a value node.
type Param struct {
	Index   int    `json:"index"`
	Name    string `json:"name"`
	ValueID string `json:"valueId"`
	// Destructured marks a parameter that binds PART of its argument rather than
	// becoming it. `f({ id, teamId })` receives one argument and binds two names out of
	// it, so several destructured parameters share one Index -- which is the whole
	// reason this flag exists: an index is no longer a unique key.
	//
	// A function whose only parameter is an object binding pattern declared NO
	// parameters at all before, so every argument handed to one bound nothing and
	// interprocedural taint stopped at the call. The options object is one of the most
	// common shapes in TypeScript; measured on documenso, 3,239 local call edges landed
	// on a callee declaring no parameters at all.
	Destructured bool `json:"destructured,omitempty"`
	// Path is the property of the argument this parameter reads, dotted for a nested
	// pattern: `{ id }` reads `id`, `{ a: { b } }` reads `a.b`, `{ id: docId }` reads
	// `id` under another name.
	//
	// Empty on a destructured parameter means the binding takes the argument WHOLE and
	// no single property names it -- a rest element (`{ ...others }`) is the shape.
	// Empty is a refusal, never a default: a caller that cannot say which property was
	// read must fall back to the whole argument (ADR-003).
	Path string `json:"path,omitempty"`
}

// ValueKind is an OPEN string, not a closed enum (ADR-001). A frontend may emit kinds
// this core does not know; unknown kinds still participate in flows.
type ValueKind string

const (
	ValueParam      ValueKind = "param"
	ValueLocal      ValueKind = "local"
	ValueProperty   ValueKind = "property"
	ValueCallResult ValueKind = "call-result"
	ValueLiteral    ValueKind = "literal"
	ValueCatchParam ValueKind = "catch-param"
	// ValueGlobal is a name with no binding inside any function: a module-level
	// declaration, or an ambient the language provides. What it identifies is a
	// container that outlives every request the process serves, which is the whole
	// evidence a retention rule has.
	ValueGlobal ValueKind = "global"
)

// Value is a dataflow node. Taint is a property of values.
type Value struct {
	ID   string    `json:"id"`
	Kind ValueKind `json:"kind"`
	Name string    `json:"name,omitempty"`
	Loc  Loc       `json:"loc"`
	Base string    `json:"base,omitempty"` // property: the root value
	Path string    `json:"path,omitempty"` // property: dotted access from Base

	// Literal is the text of a value written into the source, for the kinds that have
	// one. A call's arguments already carried their literals because a defect is often
	// visible in the call; a COMPARISON needs the same thing for the same reason, and
	// without it the decision analysis could see that a password was being measured but
	// not what it was being measured against.
	Literal string `json:"literal,omitempty"`

	// Entries are a mapping literal's members, by the key each was filed under.
	//
	// A mapping is lowered as one value with an edge in from each member, which records
	// what went IN and not what any of it is CALLED. The name is the whole of the
	// question when the mapping is a template's context: a view reads `{{ query }}`, and
	// which value that is depends entirely on the key.
	//
	// Only a key written as a literal string appears here. A computed key names nothing
	// a view can read, and guessing one would bind a value to an interpolation nobody
	// wrote.
	Entries []Entry `json:"entries,omitempty"`
}

// Entry is one member of a mapping, under the name it was filed as.
type Entry struct {
	Key     string `json:"key"`
	ValueID string `json:"valueId"`
}

// Flow is a directed intraprocedural dataflow edge. Kind is descriptive only in v0:
// it renders evidence and does not change propagation.
type Flow struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
	Loc  Loc    `json:"loc"`
	// Block is the basic block this edge occurs in, when the frontend can say so.
	//
	// A variable that is REDEFINED is lowered as a merge: one value with two edges into
	// it. Without a block on each edge the core cannot tell "the caller's body, and then
	// the verified event that replaced it" from "either of two things reached here", and
	// it reports the dead one. linkwarden's Stripe webhook is the measured case --
	// `let event = req.body` on line 46, `event = stripe.webhooks.constructEvent(...)`
	// on line 56, and a log on line 106 reported as caller-controlled through a value
	// that stopped existing fifty lines earlier. `Call` already carries this field for
	// the same reason; an assignment needed it too.
	//
	// EMPTY IS A REFUSAL, NEVER A DEFAULT. Switch arms have no graph position. Loop-body
	// flows retain the refusal until reachdef's use of the new cycles has been measured as
	// a separate change. The core reads an absent block as "position unknown" and keeps
	// the flow, which is the only safe direction for a security tool: a false negative
	// costs more than a false positive (ADR-003).
	Block string `json:"block,omitempty"`
}

// Resolution is how confidently a call site was resolved. This drives finding
// confidence and the gate (ADR-005) — severity does not.
type Resolution string

const (
	Resolved          Resolution = "resolved"
	Probable          Resolution = "probable"
	DynamicUnresolved Resolution = "dynamic-unresolved"
)

// Callee is the target of a call site.
type Callee struct {
	Kind       string `json:"kind"` // local | external | unresolved
	FunctionID string `json:"functionId,omitempty"`
	// PossibleFunctionIDs are the finite targets of an indirect call when the frontend
	// can enumerate the set but cannot name which member is selected on this request.
	// A dispatch table lookup is the canonical shape: every value in the table is known,
	// while the caller supplies the key.
	PossibleFunctionIDs []string   `json:"possibleFunctionIds,omitempty"`
	Symbol              string     `json:"symbol,omitempty"`
	Resolution          Resolution `json:"resolution"`
	// Name is what the call was WRITTEN as, independently of what it resolved to.
	//
	// An unresolved call carried no identity at all, which meant no rule could say
	// anything about one however plainly it was written. `next(err)` inside an Express
	// handler is the case that forced this: `next` is a parameter, so it resolves to
	// nothing -- and whether an error is passed to it is the difference between handing
	// the request off and carrying on with it.
	//
	// Deliberately NOT folded into Symbol. A symbol is a claim about what a name refers
	// to; this is a record of the name. Rules that match a symbol must keep matching only
	// where the frontend could say what it was.
	Name string `json:"name,omitempty"`
}

// Arg binds an argument to a value node. A positional argument has Index; a keyword
// argument has Name. FunctionID is set when the argument is a function value, which is
// what makes higher-order propagation (callbacks, promise continuations) expressible.
type Arg struct {
	Index      int    `json:"index,omitempty"`
	Name       string `json:"name,omitempty"`
	ValueID    string `json:"valueId,omitempty"`
	FunctionID string `json:"functionId,omitempty"`
}

// At reports whether this is a positional argument at index. A named argument must not
// answer a positional question: until a callee is known, its position is not known.
func (a Arg) At(index int) bool {
	return a.Name == "" && a.Index == index
}

// BoundParam resolves this argument against a known callee's declaration: the parameter
// this argument BECOMES.
//
// A destructured parameter is never the answer. Several of them share one index and none
// of them is the argument -- each is one property read out of it -- so an analysis that
// asks "which value is this argument inside the callee" has no single answer to give.
// Ask BoundParams instead.
func (a Arg) BoundParam(fn *Function) (Param, bool) {
	for _, p := range fn.Params {
		if p.Destructured {
			continue
		}
		if (a.Name != "" && p.Name == a.Name) || (a.Name == "" && p.Index == a.Index) {
			return p, true
		}
	}
	return Param{}, false
}

// BoundParams is every parameter this argument BINDS, which is not the same question as
// which parameter it becomes.
//
// `f({ id, teamId })` passes one argument and the callee binds two names out of it, each
// with the property Path it reads. A caller that only ever asked BoundParam saw nothing
// at all for such a callee, because a function whose only parameter is a binding pattern
// declares no plain parameter for the argument to become.
func (a Arg) BoundParams(fn *Function) []Param {
	var out []Param
	for _, p := range fn.Params {
		if a.Name != "" {
			// A NAMED argument binds a name the callee declared, and a destructured
			// binding's name is not one: `id` in `{ id }` is a property of the argument,
			// not a parameter a caller may address. No language lowered here has both
			// forms, and matching them would invent a binding the callee cannot receive.
			if !p.Destructured && p.Name == a.Name {
				out = append(out, p)
			}
			continue
		}
		if p.Index == a.Index {
			out = append(out, p)
		}
	}
	return out
}

// Binds reports whether this argument binds a known callee parameter.
func (a Arg) Binds(fn *Function, index int) bool {
	p, ok := a.BoundParam(fn)
	return ok && p.Index == index
}

// UnknownLiteral marks an option whose key was read and whose value was not written
// down. See Call.ArgLiterals.
const UnknownLiteral = "?"

// Call is one call site. The calls of every function together form the call graph.
type Call struct {
	ID     string `json:"id"`
	Loc    Loc    `json:"loc"`
	Callee Callee `json:"callee"`
	Args   []Arg  `json:"args"`
	// Method is the property name for a method call (`x.then(...)` -> "then"),
	// independent of how the receiver was spelled.
	Method string `json:"method,omitempty"`
	// ReceiverID is the value the method was called on. A tainted receiver is how
	// taint survives `s.trim()` and how it reaches a `.then()` continuation.
	ReceiverID string `json:"receiverValueId,omitempty"`
	ResultID   string `json:"resultValueId,omitempty"`
	Block      string `json:"block,omitempty"`
	// ConditionBranch says which result of this call enters the FIRST successor of its
	// block when the call is the direct condition of a branch: "truthy" for `if (f())`
	// and "falsy" for `if (!f())`.
	//
	// Polarity is a language fact the graph cannot recover. Without it, a failed
	// allow-list check that returns and a successful allow-list check that returns have
	// the same blocks, while only the first constrains what reaches the code after it.
	// Empty means the frontend did not state that direct relationship, and analyses must
	// decline any judgement that needs it.
	ConditionBranch string `json:"conditionBranch,omitempty"`
	// ArgLiterals holds the literal VALUE of any argument written as one, keyed by
	// argument index. `createHash("md5")` is a defect visible in the call itself with no
	// dataflow anywhere near it, and there is no way to say so without the string.
	ArgLiterals map[int]string `json:"argLiterals,omitempty"`
	// ReceiverType is the receiver's type as the frontend's checker sees it, and
	// ReceiverTypeOrigin is where that type is DECLARED — "builtin" for the
	// language's own standard library.
	//
	// This is the seam doing its job. Whether `x.delete(id)` removes a database record
	// or an entry from an in-process map is a question about the LANGUAGE, and the
	// frontend is the only side that can answer it; whether removing a record is a
	// problem is a question about security, and only the core answers that. The fact
	// lives on the call rather than on a value because a receiver often is not a
	// dataflow node at all — `this.timers` and a module-level const both reach a
	// method without ever becoming one.
	//
	// Empty means the frontend could not tell, which is never the same as "not
	// builtin": an analysis must not become confident because a frontend went quiet.
	ReceiverType       string `json:"receiverType,omitempty"`
	ReceiverTypeOrigin string `json:"receiverTypeOrigin,omitempty"`

	// UnknownLiteral is the value an option carries when its KEY was read but its value
	// was not written down: `{ password: req.body.password }` sets the option and says
	// nothing about what it is set to. An absence rule needs to see the key; a value
	// rule must never treat this as a value.
	//
	// Named here rather than spelled in three places, because the two frontends and the
	// core all have to agree about it.
	// (see EnumeratedOptions below for how a key set is known to be complete)

	// ArgCount is how many arguments were WRITTEN at the call site.
	//
	// Not the same as len(Args): an argument only appears there when it produced a
	// dataflow value, and a bare global the frontend could not resolve produces none. A
	// rule that needs to know a call was handed something -- a format string with
	// nothing to format is harmless -- cannot ask the value list, because the value list
	// is about what could be tracked rather than about what was written.
	ArgCount int `json:"argCount,omitempty"`

	// EnumeratedOptions lists the argument positions whose option KEYS this frontend
	// read in full. -1 stands for the call's keyword arguments taken as a group.
	//
	// This exists so the core can tell "this call does not set httpOnly" apart from "I
	// could not see what this call sets", which look identical in ArgLiterals and are
	// completely different claims. `res.cookie('jwt', t, getCookieOpts())` passes
	// options built somewhere else, and a missing-attribute rule that treated that as
	// absence would report four false positives in one production file -- measured, in
	// wikijs, before this field existed.
	//
	// Absence of an entry is never evidence of anything. A frontend that does not
	// populate this leaves every absence question unanswerable, which is the correct
	// answer for a frontend that cannot see (ADR-003).
	EnumeratedOptions []int `json:"enumeratedOptions,omitempty"`
}

// OptionsEnumerated reports whether this call's option keys at a position were read in
// full. Index -1 asks about keyword arguments as a group.
func (c Call) OptionsEnumerated(index int) bool {
	for _, i := range c.EnumeratedOptions {
		if i == index {
			return true
		}
	}
	return false
}

// HasArg reports whether an argument was passed at this position at all.
func (c Call) HasArg(index int) bool {
	for _, a := range c.Args {
		if a.At(index) {
			return true
		}
	}
	if _, ok := c.ArgLiterals[index]; ok {
		return true
	}
	return false
}

// EntryPoint marks where untrusted input enters. Kind is an OPEN string.
type EntryPoint struct {
	FunctionID string            `json:"functionId"`
	Kind       string            `json:"kind"`
	Framework  string            `json:"framework,omitempty"`
	Detail     map[string]string `json:"detail,omitempty"`
	// Trust is who can cause this entry point to run. Absent means REMOTE, which is
	// the conservative reading and the one every entry point had before there was
	// anything else: a frontend that says nothing must not make the core quieter.
	Trust Trust `json:"trust,omitempty"`
	// Loc is where the entry point is REGISTERED. A route exists at a place even
	// when its handler cannot be resolved, and reporting 0:0 for those makes the
	// surface unusable exactly where it is already weakest.
	Loc Loc `json:"loc,omitempty"`
	// Middleware is the chain applied to this entry point before its handler runs.
	// Cross-cutting controls live here, which is what makes them enumerable per
	// entry point rather than merely present somewhere in the file.
	Middleware []MiddlewareRef `json:"middleware,omitempty"`
	// UnresolvedParams names inputs injected into this handler whose meaning the
	// frontend could not determine, because whatever defines them is not in the
	// scanned tree.
	//
	// This is a known unknown and it is worth a great deal. A framework that injects
	// the caller's identity through an application-defined decorator puts the single
	// most important fact about an entry point behind a definition that a scan rooted
	// at one package of a monorepo cannot see. The engine then observes no identity,
	// concludes none is consulted, and reports every scoped query as unowned. Naming
	// what it could not resolve turns that from a wrong answer into a fixable one.
	UnresolvedParams []string `json:"unresolvedParams,omitempty"`
}

// TrustLevel is who can reach this entry point, reading an unstated trust as Remote.
func (e EntryPoint) TrustLevel() Trust {
	if e.Trust == "" {
		return Remote
	}
	return e.Trust
}

// MiddlewareRef is one element of an entry point's chain. Scope distinguishes a
// binding attached to this route from one applied application-wide.
type MiddlewareRef struct {
	FunctionID string `json:"functionId,omitempty"`
	Symbol     string `json:"symbol,omitempty"`
	Name       string `json:"name,omitempty"`
	Scope      string `json:"scope"` // "route" | "app"
	Loc        Loc    `json:"loc"`
}

// Ref is the stable identity of a middleware binding, used to compare chains
// across entry points.
func (m MiddlewareRef) Ref() string {
	if m.FunctionID != "" {
		return m.FunctionID
	}
	if m.Symbol != "" {
		return m.Symbol
	}
	return m.Name
}

// ReachableFromEntries returns every function an enumerated entry point can reach.
//
// Used to ask whether the surface accounts for the program: code that reads untrusted
// input and sits outside this set is code the engine believes nothing can call, which is
// either dead or evidence that a route was never enumerated.
func (ix *Index) ReachableFromEntries() map[string]bool {
	ids := make([]string, 0, len(ix.EntryByFunc))
	for id := range ix.EntryByFunc {
		ids = append(ids, id)
	}
	return ix.ReachableFrom(ids)
}

// ReachableFrom returns every function reachable from the supplied roots.
func (ix *Index) ReachableFrom(roots []string) map[string]bool {
	seen := make(map[string]bool, len(ix.FuncByID))
	var queue []string
	for _, id := range roots {
		if !seen[id] {
			seen[id] = true
			queue = append(queue, id)
		}
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		fn := ix.FuncByID[id]
		if fn == nil {
			continue
		}
		for _, c := range fn.Calls {
			if c.Callee.Kind != "local" || c.Callee.FunctionID == "" || seen[c.Callee.FunctionID] {
				continue
			}
			seen[c.Callee.FunctionID] = true
			queue = append(queue, c.Callee.FunctionID)
		}
		// A function passed as an argument is reached too: a route handler registered
		// as a callback is called by the framework, not by any call site here.
		for _, c := range fn.Calls {
			for _, a := range c.Args {
				if a.FunctionID != "" && !seen[a.FunctionID] {
					seen[a.FunctionID] = true
					queue = append(queue, a.FunctionID)
				}
			}
		}
	}
	return seen
}

// Load reads and validates an IR document.
func Load(r io.Reader) (*IR, error) {
	var doc IR
	dec := json.NewDecoder(r)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode IR: %w", err)
	}
	if err := doc.validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}

func (d *IR) validate() error {
	if d.IRVersion == "" {
		return fmt.Errorf("IR is missing irVersion")
	}
	major, _, ok := strings.Cut(d.IRVersion, ".")
	if !ok {
		return fmt.Errorf("malformed irVersion %q", d.IRVersion)
	}
	if major != fmt.Sprint(SupportedMajor) {
		return fmt.Errorf("unsupported IR major version %q (this core implements %d.x)", d.IRVersion, SupportedMajor)
	}
	if d.Frontend.Name == "" {
		return fmt.Errorf("IR is missing frontend.name")
	}
	return nil
}

// Index provides lookup over an IR, including the call graph (CallSitesOf).
type Index struct {
	IR *IR

	FuncByID  map[string]*Function
	ValueByID map[string]*Value
	CallByID  map[string]*Call

	OwnerOfValue map[string]*Function
	OwnerOfCall  map[string]*Function

	FlowsFrom   map[string][]Flow
	EntryByFunc map[string]*EntryPoint

	// CallSitesOf is the reverse call graph: callee function ID -> call sites
	// targeting it. Used to propagate a callee's tainted return to its callers.
	CallSitesOf map[string][]*Call

	// PassedAt is the other half of the reverse graph: function ID -> the call sites
	// that were HANDED it as an argument.
	//
	// Kept apart from CallSitesOf on purpose. A callback is reached from the site that
	// registers it, so the two are the same relation for a question about REACHABILITY
	// -- and they are not the same relation for a question about VALUES: a callback's
	// return does not become the registering call's result, and folding these together
	// would say it does.
	//
	// ReachableFrom has followed argument functions downward since it existed, while
	// every walk upward followed only CallSitesOf. That disagreement is what made a
	// process start unable to anchor anything: `run_sync(partial(self.start_async))`
	// hands the whole application over in one argument, so walking up from any function
	// in it reached the callback and stopped.
	PassedAt map[string][]*Call

	// TestModule marks modules the frontend identified as tests.
	TestModule map[string]bool
	// ModuleProvenance records the frontend's origin classification under both module
	// identity spellings, just as TestModule does.
	ModuleProvenance map[string]Provenance
}

// InTestModule reports whether a location sits in a module that does not run in
// production.
func (ix *Index) InTestModule(loc Loc) bool { return ix.TestModule[loc.File] }

// ProvenanceOf returns the origin classification of the module containing loc.
func (ix *Index) ProvenanceOf(loc Loc) Provenance { return ix.ModuleProvenance[loc.File] }

// InApplicationSurface reports whether a module belongs in the application's own
// attack-surface population. Generated application code may implement the deployed
// surface; examples and checked-in dependencies do not.
func (ix *Index) InApplicationSurface(loc Loc) bool {
	p := ix.ProvenanceOf(loc)
	return !ix.InTestModule(loc) && p != Vendored && p != Example && p != Tooling
}

// NewIndex builds lookup tables over an IR. It does not mutate the IR.
func NewIndex(d *IR) *Index {
	ix := &Index{
		IR:               d,
		FuncByID:         make(map[string]*Function, len(d.Functions)),
		ValueByID:        make(map[string]*Value),
		CallByID:         make(map[string]*Call),
		OwnerOfValue:     make(map[string]*Function),
		OwnerOfCall:      make(map[string]*Function),
		FlowsFrom:        make(map[string][]Flow),
		EntryByFunc:      make(map[string]*EntryPoint, len(d.EntryPoints)),
		CallSitesOf:      make(map[string][]*Call),
		PassedAt:         make(map[string][]*Call),
		TestModule:       make(map[string]bool),
		ModuleProvenance: make(map[string]Provenance),
	}
	for _, m := range d.Modules {
		if m.IsTest {
			ix.TestModule[m.Path] = true
			ix.TestModule[m.ID] = true
		}
		if m.Provenance != "" {
			ix.ModuleProvenance[m.Path] = m.Provenance
			ix.ModuleProvenance[m.ID] = m.Provenance
		}
	}
	for _, fn := range d.Functions {
		ix.FuncByID[fn.ID] = fn
		for _, v := range fn.Values {
			ix.ValueByID[v.ID] = v
			ix.OwnerOfValue[v.ID] = fn
		}
		for _, f := range fn.Flows {
			ix.FlowsFrom[f.From] = append(ix.FlowsFrom[f.From], f)
		}
		for _, c := range fn.Calls {
			ix.CallByID[c.ID] = c
			ix.OwnerOfCall[c.ID] = fn
			if c.Callee.Kind == "local" && c.Callee.FunctionID != "" {
				ix.CallSitesOf[c.Callee.FunctionID] = append(ix.CallSitesOf[c.Callee.FunctionID], c)
			}
			for _, a := range c.Args {
				if a.FunctionID != "" {
					ix.PassedAt[a.FunctionID] = append(ix.PassedAt[a.FunctionID], c)
				}
			}
		}
	}
	for i := range d.EntryPoints {
		ep := d.EntryPoints[i]
		ix.EntryByFunc[ep.FunctionID] = &ep
	}
	return ix
}
