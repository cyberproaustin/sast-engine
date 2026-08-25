// Package literal finds weaknesses visible in a written-down value and nothing else.
//
// The engine's sixth analysis kind, and the smallest. A flow asks where a value came from;
// a call shape asks what a call was written with; a store asks where a value was put.
// None of them can express an RSA private key sitting in a constant, because it is not an
// argument, it is not written into anything, and nothing reaches it. It is simply there,
// and being there is the whole of the defect.
//
// This is the kind with the least room to be wrong and the least room to be clever, and it
// is deliberately kept that way. A rule here is a shape a value either has or does not:
// `AKIA` followed by sixteen upper-case characters is an AWS key identifier and nothing
// else is. There is no entropy heuristic, no proximity to a variable named `secret`, and
// no scoring -- every one of those is a way of guessing, and a scanner that guesses about
// secrets is a scanner nobody reads twice.
//
// What that costs is real and is worth naming: a key with no recognisable shape -- a
// random thirty-character password in a constant -- is invisible here. It is caught, if at
// all, by the store and call-shape rules that watch where a literal is PUT. Silence about
// what cannot be recognised is the point (ADR-003).
package literal

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// Analyze reports every literal in the program whose own shape is a defect.
func Analyze(d *ir.IR, m model.Model) []taint.Finding {
	if len(m.Literals) == 0 {
		return nil
	}
	ix := ir.NewIndex(d)

	var out []taint.Finding
	for _, fn := range d.Functions {
		for _, v := range fn.Values {
			if v.Kind != ir.ValueLiteral || v.Literal == "" {
				continue
			}
			text := strings.TrimSpace(v.Literal)
			for _, rule := range m.Literals {
				if !rule.Matches(text) {
					continue
				}
				out = append(out, finding(ix, fn, v, rule, text))
				// One value is one finding. A private key that also parses as something
				// else is still one key written into one file, and reporting it twice
				// would say the file holds two.
				break
			}
		}
	}
	return out
}

func finding(ix *ir.Index, fn *ir.Function, v *ir.Value, rule model.LiteralRule, text string) taint.Finding {
	return taint.Finding{
		Analysis:     rule.ID,
		DataClass:    "written-value",
		ChannelID:    rule.ID,
		Class:        rule.Finding,
		CWE:          rule.CWE,
		Message:      rule.Reason,
		SinkLoc:      v.Loc,
		SinkSymbol:   rule.ID,
		SinkFunction: fn.Name,
		SinkRational: rule.Rationale,
		SourceLabel:  strconv.Quote(elide(text)),
		SourceLoc:    v.Loc,
		InTestModule: ix.InTestModule(v.Loc),
		// The evidence is the value. There is no path to walk because nothing travelled,
		// and no call to name because none was made (ADR-006).
		Path: []taint.Hop{{
			Loc:         v.Loc,
			Description: fmt.Sprintf("%s is written here", rule.Finding),
			Resolution:  ir.Resolved,
		}},
		// Written into the source, so nothing about the call graph bears on it.
		Confidence: taint.High,
		// Whether this weighs anything can turn on something the value does not carry.
		DependsOnUse: rule.DependsOnUse,
		// Like a call shape, this is an assertion about a line of code rather than over
		// the enumerated surface: a key in a file nothing routes to is still in the
		// repository, and the clone that leaks it will not care which route reached it.
		EntryAnchored: true,
		EntryPoint:    enclosing(ix, fn),
	}
}

// elide keeps a finding readable and keeps the secret out of the report. Enough of the
// value to recognise which one it is, and not enough to use.
func elide(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", "")
	if len(s) <= 24 {
		return s
	}
	return s[:24] + "..."
}

func enclosing(ix *ir.Index, fn *ir.Function) string {
	if ep, ok := ix.EntryByFunc[fn.ID]; ok {
		if m, p := ep.Detail["method"], ep.Detail["path"]; m != "" && p != "" {
			return m + " " + p
		}
	}
	return ""
}
