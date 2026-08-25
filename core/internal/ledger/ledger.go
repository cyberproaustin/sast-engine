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
	// Lists names the catalog's own priority views this weakness belongs to. Which
	// weaknesses matter most is read from MITRE rather than decided here.
	Lists []string `json:"lists"`
	// OWASP is the Top Ten category this weakness rolls into, as the catalog publishes
	// it. Derived rather than remembered: the map this replaced was written from memory
	// once and was wrong in every entry, and although a later hand-verification fixed
	// the categories, a mapping only one person has ever checked is a mapping waiting to
	// drift at the next edition.
	OWASP string `json:"owasp"`
	// ChildOf names the weaknesses this one is a more specific form of, as the catalog
	// states them. Read rather than decided, like everything else here.
	ChildOf []string `json:"childOf"`
}

// OnList reports membership of one of the catalog's priority views.
func (w Weakness) OnList(label string) bool {
	for _, l := range w.Lists {
		if l == label {
			return true
		}
	}
	return false
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
	// Subsumed: a more specific spelling of a weakness this engine asserts, where the
	// distinguishing detail is one the analysis never looks at.
	//
	// The catalog gives path traversal seventeen variants, one per payload spelling:
	// `../filedir`, `..\filedir`, `/absolute/pathname`, a Windows UNC share. An analysis
	// that proves the caller controls the path never inspects the path's CONTENTS, so
	// every one of those spellings is the same finding at the same line. Reporting them
	// as not-built would put seventeen permanent items on a to-do list that no amount of
	// work could ever remove, which is the same mistake as calling an undecidable
	// weakness pending.
	//
	// Counted separately from asserted, never folded into it. A subsumed weakness is a
	// real claim and it is a weaker one: it says the parent's rule catches this, not that
	// anybody wrote a rule for this.
	Subsumed State = "subsumed"
)

// Claim is what the engine says about one weakness and why.
type Claim struct {
	State State
	// Reason is required for anything not asserted. An uncovered weakness without a
	// stated reason is indistinguishable from one nobody thought about.
	Reason string
	// By names the policies or checks that assert it.
	By []string
	// Subsumes marks a claim whose rule catches every more specific form of the weakness
	// beneath it, because the distinguishing detail is one the analysis never looks at.
	//
	// Set on the PARENT and computed downward from the catalog's own relationships, so
	// the variants are never listed by hand. Seventeen hand-written entries would be
	// seventeen chances to be wrong and would go stale at the next release.
	Subsumes bool
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

// byID finds a published weakness. Built once, because the ancestry walk asks for
// parents far more often than there are weaknesses.
var index map[string]Weakness

func byID(id string) (Weakness, bool) {
	if index == nil {
		index = make(map[string]Weakness, len(loaded.Weaknesses))
		for _, w := range loaded.Weaknesses {
			index[w.ID] = w
		}
	}
	w, ok := index[id]
	return w, ok
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
		// A weakness this engine actually asserts belongs in the denominator whatever the
		// catalog's detection-method field says. That field is a statement about the
		// weakness in general and it is sometimes wrong about a particular decidable form
		// -- a secret compared with `===` is one -- and a coverage map that reported a
		// finding while refusing to count the weakness would be understating itself for a
		// reason no reader could work out.
		asserted := e.Claim.State == Asserted || e.Claim.State == Partial
		if e.Status == "Deprecated" || (!asserted && !e.StaticDetectable) || !e.HasCodeShape() {
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
func Covered() (asserted, subsumed, total int) {
	in := InScope()
	for _, e := range in {
		switch e.Claim.State {
		case Asserted, Partial:
			asserted++
		case Subsumed:
			// Counted apart from asserted and never folded into it. "A rule catches this"
			// and "the rule for the weakness above catches this" are different claims,
			// and adding them together would turn an honest denominator into a number
			// that flatters itself.
			subsumed++
		}
	}
	return asserted, subsumed, len(in)
}

// OWASPCategory returns the Top Ten category a weakness rolls into, or empty when the
// catalog places it in none. Empty is reported as unmapped rather than defaulted into a
// category, because a rollup that silently absorbs what it does not recognize is how a
// tool implies uniform coverage it does not have.
func OWASPCategory(cwe string) string {
	for _, w := range loaded.Weaknesses {
		if w.ID == cwe {
			return w.OWASP
		}
	}
	return ""
}

// TopTwentyFive is the catalog's own list of the weaknesses that matter most.
const TopTwentyFive = "cwe-top-25-2025"

// CoveredOnList is how much of a priority view the engine asserts, counted against the
// CategoryCoverage is how much of one rollup category this build has rules for.
type CategoryCoverage struct {
	Category string
	Asserted int
	Total    int
}

// CoverageByCategory answers the question a finding count cannot: is a category quiet
// because the code is clean, or because nothing checks it?
//
// A rollup listing only the categories with findings reads as coverage of the ones it
// names and silence about the rest, and a reader has no way to tell "nothing found here"
// from "nothing looked here". Both are worth knowing and they are not the same thing.
func CoverageByCategory() []CategoryCoverage {
	byCat := map[string]*CategoryCoverage{}
	for _, e := range InScope() {
		cat := OWASPCategory(e.Weakness.ID)
		if cat == "" {
			continue
		}
		c := byCat[cat]
		if c == nil {
			c = &CategoryCoverage{Category: cat}
			byCat[cat] = c
		}
		c.Total++
		if e.Claim.State == Asserted || e.Claim.State == Partial {
			c.Asserted++
		}
	}
	out := make([]CategoryCoverage, 0, len(byCat))
	for _, c := range byCat {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
	return out
}

// members a rule could be written for rather than against all of them: several are C
// memory-safety weaknesses that no frontend here will ever parse, and counting those as
// gaps would make the number meaningless in the flattering direction as well as the
// unflattering one.
func CoveredOnList(label string) (asserted, total int) {
	for _, e := range InScope() {
		if !e.OnList(label) {
			continue
		}
		total++
		if e.Claim.State == Asserted || e.Claim.State == Partial {
			asserted++
		}
	}
	return asserted, total
}

// MissingFromList names the members of a priority view the engine does not yet assert,
// which is the only prioritised to-do list in this project that nobody wrote by hand.
func MissingFromList(label string) []Entry {
	var out []Entry
	for _, e := range InScope() {
		if e.OnList(label) && e.Claim.State != Asserted && e.Claim.State != Partial {
			out = append(out, e)
		}
	}
	return out
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
