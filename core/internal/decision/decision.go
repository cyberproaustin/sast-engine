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
					if rule.OtherIsText && !isText(ix.ValueByID[other]) {
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
				// A rule about a THRESHOLD needs the threshold, and a comparison against
				// something computed at runtime has none to read.
				if rule.OtherBelow != nil && !numberBelow(ix.ValueByID[other], *rule.OtherBelow) {
					continue
				}
				if rule.OtherIsText && !isText(ix.ValueByID[other]) {
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

// numberBelow reports whether a value is a number written into the source and smaller
// than a threshold. Anything else -- a name, a call, a value the frontend could not read
// -- is not a number written into the source.
func numberBelow(v *ir.Value, threshold int) bool {
	if v == nil || v.Kind != ir.ValueLiteral || v.Literal == "" {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v.Literal))
	return err == nil && n < threshold
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
