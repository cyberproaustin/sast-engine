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
	TypeChecker     bool     `json:"typeChecker"`
	Interprocedural bool     `json:"interprocedural"`
	CrossModule     bool     `json:"crossModule"`
	ControlFlow     bool     `json:"controlFlow"`
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
}

// Loc is a source position. Line and Column are 1-based.
type Loc struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

func (l Loc) String() string { return fmt.Sprintf("%s:%d:%d", l.File, l.Line, l.Column) }

// Function is the unit of intraprocedural dataflow.
type Function struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Module     string   `json:"module"`
	Loc        Loc      `json:"loc"`
	Params     []Param  `json:"params"`
	Values     []*Value `json:"values"`
	Flows      []Flow   `json:"flows"`
	Calls      []*Call  `json:"calls"`
	Returns    []string `json:"returns"`
	EntryBlock string   `json:"entryBlock,omitempty"`
	Blocks     []Block  `json:"blocks,omitempty"`
	// Comparisons are relational facts: which values were tested against which.
	// Dataflow alone cannot see that a handler checked one thing against another,
	// and "was this related to the caller's identity?" is exactly that question.
	Comparisons []Comparison `json:"comparisons,omitempty"`
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
}

// Param is a formal parameter bound to a value node.
type Param struct {
	Index   int    `json:"index"`
	Name    string `json:"name"`
	ValueID string `json:"valueId"`
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
)

// Value is a dataflow node. Taint is a property of values.
type Value struct {
	ID   string    `json:"id"`
	Kind ValueKind `json:"kind"`
	Name string    `json:"name,omitempty"`
	Loc  Loc       `json:"loc"`
	Base string    `json:"base,omitempty"` // property: the root value
	Path string    `json:"path,omitempty"` // property: dotted access from Base
}

// Flow is a directed intraprocedural dataflow edge. Kind is descriptive only in v0:
// it renders evidence and does not change propagation.
type Flow struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
	Loc  Loc    `json:"loc"`
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
	Kind       string     `json:"kind"` // local | external | unresolved
	FunctionID string     `json:"functionId,omitempty"`
	Symbol     string     `json:"symbol,omitempty"`
	Resolution Resolution `json:"resolution"`
}

// Arg binds a positional argument to a value node. FunctionID is set when the
// argument is a function value, which is what makes higher-order propagation
// (callbacks, promise continuations) expressible.
type Arg struct {
	Index      int    `json:"index"`
	ValueID    string `json:"valueId,omitempty"`
	FunctionID string `json:"functionId,omitempty"`
}

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
}

// EntryPoint marks where untrusted input enters. Kind is an OPEN string.
type EntryPoint struct {
	FunctionID string            `json:"functionId"`
	Kind       string            `json:"kind"`
	Framework  string            `json:"framework,omitempty"`
	Detail     map[string]string `json:"detail,omitempty"`
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
	seen := make(map[string]bool, len(ix.FuncByID))
	var queue []string
	for id := range ix.EntryByFunc {
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

	// TestModule marks modules the frontend identified as tests.
	TestModule map[string]bool
}

// InTestModule reports whether a location sits in a module that does not run in
// production.
func (ix *Index) InTestModule(loc Loc) bool { return ix.TestModule[loc.File] }

// NewIndex builds lookup tables over an IR. It does not mutate the IR.
func NewIndex(d *IR) *Index {
	ix := &Index{
		IR:           d,
		FuncByID:     make(map[string]*Function, len(d.Functions)),
		ValueByID:    make(map[string]*Value),
		CallByID:     make(map[string]*Call),
		OwnerOfValue: make(map[string]*Function),
		OwnerOfCall:  make(map[string]*Function),
		FlowsFrom:    make(map[string][]Flow),
		EntryByFunc:  make(map[string]*EntryPoint, len(d.EntryPoints)),
		CallSitesOf:  make(map[string][]*Call),
		TestModule:   make(map[string]bool),
	}
	for _, m := range d.Modules {
		if m.IsTest {
			ix.TestModule[m.Path] = true
			ix.TestModule[m.ID] = true
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
		}
	}
	for i := range d.EntryPoints {
		ep := d.EntryPoints[i]
		ix.EntryByFunc[ep.FunctionID] = &ep
	}
	return ix
}
