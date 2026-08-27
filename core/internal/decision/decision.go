// Package decision finds weaknesses in what a branch was decided ON.
//
// The engine's fourth analysis kind, and the smallest. A flow analysis asks where data
// goes and a call-shape analysis asks what a call was given; this asks what a program
// BELIEVED. `if (req.body.role === "admin")` sends nothing anywhere and calls nothing
// dangerous -- the whole defect is that the server took the caller's word about the
// caller.
//
// It runs on the same taint the flow analysis produces, so a claim that was passed
// through three functions before being tested is still recognised as the caller's. What
// it adds is the comparison: the IR has recorded those all along and nothing read them.
package decision

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// Analyze reports comparisons that decide something on a value of a classified kind.
//
// tainted maps a classification to the values carrying it, which is what the flow
// analysis already computed. Recomputing it here would be a second answer to a question
// that has one.
func Analyze(d *ir.IR, m model.Model, byClass map[string]taint.Classified) []taint.Finding {
	if len(m.Decisions) == 0 {
		return nil
	}
	ix := ir.NewIndex(d)
	// Which call produced which value, for a rule that asks what a compared value was
	// computed FROM.
	resultOf := make(map[string]*ir.Call)
	for _, fn := range d.Functions {
		for _, c := range fn.Calls {
			if c.ResultID != "" {
				resultOf[c.ResultID] = c
			}
		}
	}

	var out []taint.Finding
	for _, fn := range d.Functions {
		for _, cmp := range fn.Comparisons {
			for _, rule := range m.Decisions {
				if !operatorMatches(rule, cmp.Op) {
					continue
				}
				// A rule with no class is about the COMPARISON, not about what is being
				// compared, so there is no classified side to find and either side may
				// carry the literal.
				var carrying taint.Classified
				side, other := "", ""
				if rule.Class == "" {
					side, other = cmp.Left, cmp.Right
					// A rule with no class finds its side by what PRODUCED it.
					if len(rule.SideFrom) > 0 && !producedBy(resultOf, side, rule.SideFrom) {
						side, other = cmp.Right, cmp.Left
					}
					if rule.OtherIsText && !isText(ix.ValueByID[other]) {
						side, other = cmp.Right, cmp.Left
					}
					if len(rule.OtherNamed) > 0 && !namedOneOf(ix, other, rule.OtherNamed) {
						side, other = cmp.Right, cmp.Left
					}
				} else {
					carrying = byClass[rule.Class]
					if carrying.Values == nil {
						continue
					}
					// Either side. `role === "admin"` and `"admin" === role` are the same
					// decision, and which way round it was written is not evidence of
					// anything.
					switch {
					case carrying.Values[cmp.Left]:
						side, other = cmp.Left, cmp.Right
					case carrying.Values[cmp.Right]:
						side, other = cmp.Right, cmp.Left
					default:
						continue
					}
				}
				if len(rule.SideFrom) > 0 && !producedBy(resultOf, side, rule.SideFrom) {
					continue
				}
				if len(rule.OtherClasses) > 0 && !carriesAnyClass(byClass, other, rule.OtherClasses) {
					continue
				}
				// A rule about a THRESHOLD needs the threshold, and a comparison against
				// something computed at runtime has none to read.
				if rule.OtherBelow != nil && !numberBelow(ix.ValueByID[other], *rule.OtherBelow) {
					continue
				}
				// A threshold, not a presence test.
				if rule.OtherAtLeast != nil && numberBelow(ix.ValueByID[other], *rule.OtherAtLeast) {
					continue
				}
				if rule.OtherIsText && !isText(ix.ValueByID[other]) {
					continue
				}
				// A field read off something the credential produced is not the
				// credential.
				if rule.RequiresUnprojected && carrying.Projected[side] {
					continue
				}
				// A particular derivation of the classified value, named by the property
				// leaf or by the function that produced it -- and taken of the classified
				// value ITSELF rather than of anything the program later computed from
				// it. A password's length is the password's; the length of a path that a
				// password was once involved in producing is not.
				if len(rule.SideVia) > 0 {
					src, ok := derivedVia(ix, resultOf, ix.ValueByID[side], rule.SideVia)
					// The value it was taken OF must be the classified thing rather than
					// something read out of it: `password.length` where `password` is the
					// field the caller sent, not `parts.length` where `parts` is what a
					// library made of it four frames later.
					if !ok || !carrying.Values[src] || carrying.Projected[src] {
						continue
					}
				}
				// Two values the same caller just sent, compared against each other:
				// a confirmation field, not a secret check.
				if rule.OtherNotSameClass && carrying.Values[other] &&
					!carriesAnyClass(byClass, other, rule.OtherClassOverridesSame) {
					continue
				}
				if len(rule.OtherNamed) > 0 && !namedOneOf(ix, other, rule.OtherNamed) {
					continue
				}
				if len(rule.OtherNameContains) > 0 && !nameContainsOneOf(ix.ValueByID[other], rule.OtherNameContains) {
					continue
				}
				if rule.OtherNotLiteral && writtenDown(ix.ValueByID[other]) {
					continue
				}
				// A test for nothing at all is not a test of what the value stands for.
				if rule.OtherNotAbsent && absentValue(ix.ValueByID[other]) {
					continue
				}
				o := carrying.Origin[side]
				// A rule with no class has no source to name, so the evidence is the
				// literal that was compared -- which is the whole of what was written.
				if rule.Class == "" {
					if v := ix.ValueByID[other]; v != nil && v.Literal != "" {
						o.Label = fmt.Sprintf("%q", v.Literal)
					}
				}
				out = append(out, finding(ix, fn, cmp, rule, o))
			}
		}
	}
	return out
}

func carriesAnyClass(byClass map[string]taint.Classified, id string, classes []string) bool {
	for _, class := range classes {
		if byClass[class].Values[id] {
			return true
		}
	}
	return false
}

// nameContainsOneOf reads the name the program gave a value, with separators removed so
// ahmia_blacklist and ahmiaBlacklist are the same evidence. Used only after the other
// operand has independently been classified, never to turn a name into a finding alone.
func nameContainsOneOf(v *ir.Value, wants []string) bool {
	if v == nil {
		return false
	}
	name := strings.ToLower(v.Path)
	if name == "" {
		name = strings.ToLower(v.Name)
	}
	name = strings.NewReplacer("_", "", "-", "").Replace(name)
	for _, want := range wants {
		want = strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(want))
		if strings.Contains(name, want) {
			return true
		}
	}
	return false
}

// numberBelow reports whether a value is a number written into the source and smaller
// than a threshold. Anything else -- a name, a call, a value the frontend could not read
// -- is not a number written into the source.
func numberBelow(v *ir.Value, threshold int) bool {
	if v == nil || v.Kind != ir.ValueLiteral || v.Literal == "" {
		return false
	}
	// Parsed as a real rather than an integer: `len(password) < 6.0` is below eight, and
	// an integer parse rejects it outright.
	n, err := strconv.ParseFloat(strings.TrimSpace(v.Literal), 64)
	return err == nil && n < float64(threshold)
}

// derivedVia reports whether a value is a named derivation of something else: a property
// read whose leaf is one of these, or the result of calling one of them.
//
// `password.length` and `len(password)` are the same question asked in two languages, and
// the whole of what a rule about a password's LENGTH is entitled to look at.
func derivedVia(ix *ir.Index, resultOf map[string]*ir.Call, v *ir.Value, names []string) (string, bool) {
	if v == nil {
		return "", false
	}
	if v.Kind == ir.ValueProperty && matchesName(v.Path, names) {
		return v.Base, true
	}
	if c := resultOf[v.ID]; c != nil && matchesName(c.Callee.Symbol, names) {
		for _, a := range c.Args {
			if a.Index == 0 {
				return a.ValueID, true
			}
		}
	}
	return "", false
}

// producedBy reports whether a value is the result of a call to one of these symbols.
func producedBy(resultOf map[string]*ir.Call, id string, symbols []string) bool {
	c := resultOf[id]
	if c == nil {
		return false
	}
	name := c.Callee.Symbol
	if name == "" {
		name = c.Method
	}
	for _, want := range symbols {
		if strings.EqualFold(name, want) || strings.EqualFold(leafOf(name), leafOf(want)) {
			return true
		}
	}
	return false
}

func leafOf(s string) string {
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// writtenDown reports whether the other side of a comparison is something the author
// PUT THERE rather than something the program computed.
//
// A literal is the obvious case. `undefined`, `null` and `NaN` are the other one: the
// language provides them and nothing computes them, so `token === undefined` is a
// presence test exactly as `token === ""` is -- and a rule that excludes the first must
// exclude the second. They started reaching rules at all only when bare language names
// began to be lowered, which is why this is stated here rather than assumed.
func writtenDown(v *ir.Value) bool {
	if v == nil || v.Kind == ir.ValueLiteral {
		return true
	}
	switch strings.ToLower(v.Name) {
	case "undefined", "null", "nan", "none":
		return true
	}
	return false
}

// absentValue reports whether a value is the language's way of writing NOTHING: an empty
// string, or one of the names the language provides for absence.
//
// The empty literal has to be read from the KIND rather than from the text, because an
// unrecorded literal and an empty one are the same empty string otherwise -- and only one
// of them is evidence.
func absentValue(v *ir.Value) bool {
	if v == nil {
		return false
	}
	if v.Kind == ir.ValueLiteral && strings.TrimSpace(v.Literal) == "" {
		return true
	}
	switch strings.ToLower(v.Name) {
	case "none", "null", "undefined", "nan":
		return true
	}
	return false
}

// namedOneOf reports whether a value IS one of these names -- `NaN`, `math.nan`. The
// name is all there is: the language provides the value and there is no literal to read.
func namedOneOf(ix *ir.Index, id string, names []string) bool {
	v := ix.ValueByID[id]
	if v == nil {
		return false
	}
	for _, want := range names {
		if strings.EqualFold(v.Path, want) || strings.EqualFold(v.Name, want) {
			return true
		}
		if i := strings.LastIndexByte(want, '.'); i >= 0 {
			leaf := want[i+1:]
			if strings.EqualFold(v.Path, leaf) || strings.EqualFold(v.Name, leaf) {
				return true
			}
		}
	}
	return false
}

func matchesName(dotted string, names []string) bool {
	leaf := dotted
	if i := strings.LastIndex(leaf, "."); i >= 0 {
		leaf = leaf[i+1:]
	}
	leaf = strings.ToLower(leaf)
	for _, want := range names {
		if leaf == strings.ToLower(want) {
			return true
		}
	}
	return false
}

// isText reports whether a value is a STRING written into the source. A number is
// written the same way and is not one: `x is 5` is a different question with a different
// answer, and small integers are interned where strings are not.
func isText(v *ir.Value) bool {
	if v == nil || v.Kind != ir.ValueLiteral || v.Literal == "" {
		return false
	}
	if _, err := strconv.ParseFloat(strings.TrimSpace(v.Literal), 64); err == nil {
		return false
	}
	return v.Literal != "true" && v.Literal != "false" && v.Literal != "null" && v.Literal != "None"
}

// operatorMatches reports whether this rule cares about the operator used. A rule that
// names none accepts any.
func operatorMatches(rule model.DecisionRule, op string) bool {
	if len(rule.Ops) == 0 {
		return true
	}
	for _, want := range rule.Ops {
		if want == op {
			return true
		}
	}
	return false
}

func finding(ix *ir.Index, fn *ir.Function, cmp ir.Comparison, rule model.DecisionRule, o taint.Origin) taint.Finding {
	return taint.Finding{
		Analysis:      rule.ID,
		DataClass:     rule.Class,
		ChannelID:     rule.ID,
		Class:         rule.Finding,
		CWE:           rule.CWE,
		Message:       rule.Reason,
		Confidence:    taint.High,
		SourceLoc:     cmp.Loc,
		SourceLabel:   o.Label,
		EntryPoint:    o.EntryPoint,
		EntryMethod:   o.Method,
		EntryPath:     o.Path,
		EntryAnchored: o.Anchored,
		EntryTrust:    o.Trust,
		InTestModule:  ix.InTestModule(cmp.Loc),
		SinkLoc:       cmp.Loc,
		SinkFunction:  fn.Name,
		SinkSymbol:    fmt.Sprintf("comparison %s", cmp.Op),
		SinkRational:  rule.Rationale,
		Path: []taint.Hop{{
			Loc:         cmp.Loc,
			Description: fmt.Sprintf("decided by comparing with %s", cmp.Op),
			Resolution:  ir.Resolved,
		}},
	}
}
