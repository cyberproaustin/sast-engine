// Package store finds weaknesses in what got WRITTEN somewhere.
//
// The engine's fifth analysis kind, and like the fourth it exists because a real weakness
// has no call and no comparison in it. `req.session.role = req.body.role` calls nothing
// and compares nothing: the caller's claim is moved to the far side of a trust boundary,
// and everything downstream that reads the session gets it back looking like state the
// server established.
//
// The IR recorded assignments to plain names and nothing else until this needed them, so
// a write into a property or a subscript was invisible -- which is to say the weakness was
// not merely unbuilt but unexpressible.
package store

import (
	"fmt"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// Analyze reports classified values written into a named destination.
func Analyze(d *ir.IR, m model.Model, byClass map[string]taint.Classified) []taint.Finding {
	if len(m.Stores) == 0 {
		return nil
	}
	ix := ir.NewIndex(d)

	var out []taint.Finding
	for _, fn := range d.Functions {
		for _, w := range fn.Writes {
			if w.From == "" {
				continue
			}
			for _, rule := range m.Stores {
				if !intoMatches(ix, w, rule) {
					continue
				}
				if len(rule.NotInto) > 0 && intoMatches(ix, w, model.StoreRule{Into: rule.NotInto}) {
					continue
				}
				if len(rule.Path) > 0 && !pathMatches(w.Path, rule.Path) {
					continue
				}
				if pathMatches(w.Path, rule.NotPath) {
					continue
				}
				carrying := byClass[rule.Class]
				if !carrying.Values[w.From] {
					continue
				}
				out = append(out, finding(ix, fn, w, rule, carrying.Origin[w.From]))
			}
		}
	}
	return out
}

// intoMatches asks what is being written INTO, by the last segment of the base's access
// path. `req.session` and `request.session` are both a session, and which parameter the
// framework happened to hand it on is not the question.
func intoMatches(ix *ir.Index, w ir.Write, rule model.StoreRule) bool {
	base := ix.ValueByID[w.Base]
	if base == nil {
		return false
	}
	name := base.Path
	if name == "" {
		name = base.Name
	}
	if i := lastDot(name); i >= 0 {
		name = name[i+1:]
	}
	// A rule that names no destination is about the FIELD rather than the object holding
	// it. `user.role = req.body.role` and `account.isAdmin = req.body.isAdmin` are the
	// same weakness written on two different records, and enumerating what a record can
	// be called would be a list that is wrong the moment somebody names one differently.
	if len(rule.Into) == 0 {
		return true
	}
	for _, want := range rule.Into {
		if name == want {
			return true
		}
	}
	return false
}

// pathMatches narrows to particular keys written into a destination. The environment
// holds a hundred harmless variables and a few that decide where the next program comes
// from.
//
// Compared on the LAST segment and ignoring separators, so `is_admin`, `isAdmin` and
// `user.isAdmin` are one name. The source rules already read field names this way, and a
// rule that read them differently on the way in and on the way out would be two rules
// wearing one name.
func pathMatches(path string, want []string) bool {
	leaf := path
	if i := lastDot(leaf); i >= 0 {
		leaf = leaf[i+1:]
	}
	bare := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(leaf))
	for _, w := range want {
		if path == w || bare == strings.ToLower(w) {
			return true
		}
	}
	return false
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

func finding(ix *ir.Index, fn *ir.Function, w ir.Write, rule model.StoreRule, o taint.Origin) taint.Finding {
	return taint.Finding{
		Analysis:      rule.ID,
		DataClass:     rule.Class,
		ChannelID:     rule.ID,
		Class:         rule.Finding,
		CWE:           rule.CWE,
		Message:       rule.Reason,
		Confidence:    taint.High,
		SourceLoc:     w.Loc,
		SourceLabel:   o.Label,
		EntryPoint:    o.EntryPoint,
		EntryMethod:   o.Method,
		EntryPath:     o.Path,
		EntryAnchored: o.Anchored,
		InTestModule:  ix.InTestModule(w.Loc),
		SinkLoc:       w.Loc,
		SinkFunction:  fn.Name,
		SinkSymbol:    fmt.Sprintf("write to %s", w.Path),
		SinkArgIndex:  -1,
		SinkRational:  rule.Rationale,
		Path: []taint.Hop{{
			Loc:         w.Loc,
			Description: fmt.Sprintf("written into %s", w.Path),
			Resolution:  ir.Resolved,
		}},
	}
}
