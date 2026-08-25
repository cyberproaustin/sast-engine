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
		servesRequest := reachedFromEntry(ix, fn)
		for _, w := range fn.Writes {
			if w.From == "" {
				continue
			}
			for _, rule := range m.Stores {
				// "Did this value come from a request" and "did this line run while
				// serving one" are different questions, and only the second one makes a
				// write into shared state a cross-request leak.
				if rule.RequiresEntryFunction && !servesRequest {
					continue
				}
				if rule.IntoScope != "" {
					if w.Scope != rule.IntoScope {
						continue
					}
				} else if !intoMatches(ix, w, rule) {
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
				if len(rule.PathContains) > 0 &&
					(containsWord(w.Path, rule.PathExcept) || !containsWord(w.Path, rule.PathContains)) {
					continue
				}
				// A rule about what was WRITTEN DOWN needs no classification: being a
				// literal is the defect, and a value read from the environment is not one.
				if rule.FromLiteral {
					v := ix.ValueByID[w.From]
					if v == nil || v.Kind != ir.ValueLiteral || !meaningfulSecret(v.Literal) {
						continue
					}
					out = append(out, finding(ix, fn, w, rule, taint.Origin{Label: quoted(v.Literal)}))
					continue
				}
				carrying := byClass[rule.Class]
				if !carrying.Values[w.From] {
					continue
				}
				// A field read out of something the classification reached is not the
				// classified thing. A server-side lookup handed a request once does not
				// make its answer the caller's.
				if rule.RequiresUnprojected && carrying.Projected[w.From] {
					continue
				}
				out = append(out, finding(ix, fn, w, rule, carrying.Origin[w.From]))
			}
		}
	}
	return out
}

// reachedFromEntry reports whether a function is a request handler or is called by one,
// within a few hops. Bounded on purpose: past three calls the answer stops being evidence
// that this line runs per-request and starts being evidence that the program is connected.
func reachedFromEntry(ix *ir.Index, fn *ir.Function) bool {
	seen := map[string]bool{fn.ID: true}
	frontier := []*ir.Function{fn}
	for depth := 0; depth < 2 && len(frontier) > 0; depth++ {
		var next []*ir.Function
		for _, f := range frontier {
			if _, ok := ix.EntryByFunc[f.ID]; ok {
				return true
			}
			for _, site := range ix.CallSitesOf[f.ID] {
				caller := ix.OwnerOfCall[site.ID]
				if caller == nil || seen[caller.ID] {
					continue
				}
				seen[caller.ID] = true
				next = append(next, caller)
			}
		}
		frontier = next
	}
	return false
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

// containsWord reports whether an access path contains one of these words, ignoring case
// and separators, so `SECRET_KEY_HMAC` and `secretKey` both contain `secret`.
func containsWord(path string, words []string) bool {
	lower := strings.ToLower(path)
	for _, w := range words {
		if strings.Contains(lower, strings.ToLower(w)) {
			return true
		}
	}
	return false
}

// meaningfulSecret rejects the values that are a placeholder rather than a key. A config
// key set to None, to the empty string or to a flag is a key that is not set.
func meaningfulSecret(literal string) bool {
	v := strings.TrimSpace(strings.ToLower(literal))
	switch v {
	case "", "none", "null", "true", "false", "0", "1", "undefined", "changeme":
		return false
	}
	if len(v) < 4 {
		return false
	}
	// A secret is one opaque run of characters. These three shapes are what a key-named
	// setting holds when it is NOT holding a key, and each was measured on the clean
	// corpus: an endpoint the credential is sent TO, a sentence explaining that a
	// credential is required, and the mask a value is replaced with before it is logged.
	// An endpoint the credential is sent TO, not the credential.
	if strings.Contains(v, "://") {
		return false
	}
	// A sentence, not a key. Three or more words is the line: a real key is one run of
	// characters and occasionally two, and a passphrase written into the source is still
	// short -- while "either password or private_key is required" is a validation message
	// being assigned, which is what this shape looks like in a settings schema. Measured on
	// the clean corpus, and deliberately not "contains a space": Flask's own documented
	// example secret key has one in it.
	if len(strings.Fields(v)) > 2 {
		return false
	}
	// The mask a value is replaced with before it is logged, which is the one literal a
	// secret-named setting holds precisely BECAUSE the real secret must not be there.
	return strings.TrimLeft(v, v[:1]) != ""
}

func quoted(s string) string { return "\"" + s + "\"" }

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
