// Package ledger is the engine's account of the whole CWE catalog: what it asserts, what
// it has not built, and what nothing of this kind could ever decide.
//
// The catalog half is generated from MITRE's published release (catalog/generate.py) and
// no identifier or name is ever typed by hand. The claim half lives in coverage.go and is
// keyed by id, so adopting a new CWE release is a regeneration rather than a merge.
//
// The point of holding the WHOLE catalog rather than the part we cover is ADR-007 taken to
// its conclusion. A coverage map listing only what a tool can do is marketing; one that
// lists 969 weaknesses and says which are asserted, which are unbuilt, and which are out
// of reach is the difference between a tool with an honest denominator and a tool with a
// number nobody can check.
package ledger

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
)

//go:embed cwe.json
var catalogJSON []byte

// Weakness is one CWE entry as MITRE publishes it.
type Weakness struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Abstraction string `json:"abstraction"` // Pillar | Class | Base | Variant | Compound
	Status      string `json:"status"`
	// StaticDetectable is MITRE's own judgement that a tool can find this.
	StaticDetectable bool     `json:"staticDetectable"`
	Languages        []string `json:"languages"`
	LanguageAgnostic bool     `json:"languageAgnostic"`
}

// HasCodeShape reports whether a rule can be written against this entry at all. Pillars
// and Classes are abstractions over other weaknesses; covering their children covers them.
func (w Weakness) HasCodeShape() bool {
	return w.Abstraction == "Base" || w.Abstraction == "Variant"
}

// State is what this engine claims about a weakness.
type State string

const (
	// Asserted: a rule checks this and its cost has been measured on real code.
	Asserted State = "asserted"
	// Partial: checked only under conditions - a modeled framework, a resolvable call.
	Partial State = "partial"
	// NotBuilt: a rule could be written and has not been. The honest default.
	NotBuilt State = "not-built"
	// Undecidable: no static analysis of source could decide it. Intent, deployment,
	// documentation, a running system's behaviour.
	Undecidable State = "undecidable"
	// OutOfScope: real, decidable, and about a language or platform this engine has no
	// frontend for.
	OutOfScope State = "out-of-scope"
	// Abstract: a Pillar or Class, covered by covering its children rather than directly.
	Abstract State = "abstract"
)

// Claim is what the engine says about one weakness and why.
type Claim struct {
	State State
	// Reason is required for anything not asserted. An uncovered weakness without a
	// stated reason is indistinguishable from one nobody thought about.
	Reason string
	// By names the policies or checks that assert it.
	By []string
}

// Entry joins a published weakness to this engine's claim about it.
type Entry struct {
	Weakness
	Claim
}

type catalog struct {
	Source     string     `json:"source"`
	Version    string     `json:"version"`
	Date       string     `json:"date"`
	Weaknesses []Weakness `json:"weaknesses"`
}

var loaded catalog

func init() {
	if err := json.Unmarshal(catalogJSON, &loaded); err != nil {
		panic(fmt.Sprintf("ledger: embedded CWE catalog is unreadable: %v", err))
	}
}

// Edition identifies the catalog release this build reports against.
func Edition() string { return "CWE " + loaded.Version + " (" + loaded.Date + ")" }

// All returns every weakness with the engine's claim about it, in id order.
func All() []Entry {
	out := make([]Entry, 0, len(loaded.Weaknesses))
	for _, w := range loaded.Weaknesses {
		out = append(out, Entry{Weakness: w, Claim: claimFor(w)})
	}
	return out
}

// InScope is the set a rule could be written for: it has a code shape, static analysis
// could find it, it is not deprecated, and it is not about a language we cannot parse.
// This is the denominator every coverage number in this project is reported against.
func InScope() []Entry {
	var out []Entry
	for _, e := range All() {
		if e.Status == "Deprecated" || !e.StaticDetectable || !e.HasCodeShape() {
			continue
		}
		if e.Claim.State == OutOfScope {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Counts summarizes the ledger by state.
func Counts(entries []Entry) map[State]int {
	out := map[State]int{}
	for _, e := range entries {
		out[e.Claim.State]++
	}
	return out
}

// Covered is the fraction of in-scope weaknesses the engine asserts, whole or partial.
func Covered() (asserted, total int) {
	in := InScope()
	for _, e := range in {
		if e.Claim.State == Asserted || e.Claim.State == Partial {
			asserted++
		}
	}
	return asserted, len(in)
}

// Assertions lists what the engine claims, in id order, for the report.
func Assertions() []Entry {
	var out []Entry
	for _, e := range All() {
		if e.Claim.State == Asserted || e.Claim.State == Partial {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
