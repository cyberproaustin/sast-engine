// Package expectation decides what controls an entry point ought to have, and reports
// the ones that fall short.
//
// An expectation has an ORIGIN, and the origin decides what it is worth (ADR-011):
//
//	inferred — the population says so (ADR-010). Informs; never gates.
//	declared — the team wrote it down (ADR-013). Gates.
//
// The asymmetry is deliberate. Inference is a good guess about intent and should not
// stop a build on a guess. A team that stated its expectation has earned an enforceable
// claim, and a violation of it is unambiguous.
package expectation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/policy"
	"github.com/cyberproaustin/sast-engine/core/internal/surface"
)

// weaknessFor names what is missing, rather than labelling every gap with the same
// identity.
//
// The same principle the channels follow (ADR-012): the judgement is one judgement -- this
// entry point lacks something its peers have -- and what makes it a particular weakness is
// WHAT was lacking. An absent authentication control is CWE-306; an absent authorization
// control is CWE-862; and a control the engine could not classify is honestly reported as
// the class above both of them, because that is genuinely all that is known.
func weaknessFor(controlKind string) string {
	switch controlKind {
	case "authentication":
		return "CWE-306"
	case "authorization":
		return "CWE-862"
	case "rate-limit":
		return "CWE-770"
	case "csrf":
		return "CWE-352"
	default:
		return "CWE-284"
	}
}

// weaknessAt narrows the identity by WHERE the control is missing.
//
// A missing throttle is unbounded resource consumption in general and something sharper on
// an authentication endpoint: unlimited attempts against a login is how a password gets
// guessed, and the remedy is the same shape but the urgency is not. The path is the only
// evidence available at this point and it is used to narrow an identity rather than to
// make a finding, so the worst it does is report the general number where the specific one
// applied.
func weaknessAt(controlKind, path string) string {
	if controlKind != "rate-limit" || !looksLikeAuthentication(path) {
		return weaknessFor(controlKind)
	}
	return "CWE-307"
}

// looksLikeAuthentication reports whether a route path is one where credentials are
// presented. Deliberately a short list of segments rather than anything clever: these are
// the words applications actually use, and a longer list would start guessing.
func looksLikeAuthentication(path string) bool {
	lower := strings.ToLower(path)
	for _, seg := range []string{"login", "signin", "sign-in", "authenticate", "session", "token", "password/reset", "otp", "mfa", "2fa"} {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	return false
}

// applies reports whether a control is one THIS entry point ought to carry, independently
// of what its peers do.
//
// The population answers "is this control expected around here" and cannot answer "is it
// expected of this route", and for one control kind the difference matters. An anti-CSRF
// token exists to prove a state-changing request was intended; a GET is not supposed to
// change state, and every CSRF middleware worth the name -- csurf included -- lets safe
// methods through without a token. Flagging a read for lacking one reports the library's
// own documented behaviour as a defect.
//
// Every other control kind applies to a read exactly as it applies to a write: an
// unauthenticated GET is still unauthenticated.
func applies(kind string, e surface.EntryFacts) bool {
	if kind != "csrf" {
		return true
	}
	switch strings.ToUpper(e.Method) {
	case "GET", "HEAD", "OPTIONS":
		return false
	}
	return true
}

// entryPath is the route an entry point serves, or its label when the framework gave it
// none.
func entryPath(e surface.EntryFacts) string {
	if e.Path != "" {
		return e.Path
	}
	return e.Label()
}

// Origins.
const (
	OriginInferred = "inferred"
	OriginDeclared = "declared"
)

// Thresholds control how strong a population has to be before its behavior is taken as
// an expectation. Conservative on purpose: a wrong inference reports code that is fine.
type Thresholds struct {
	MinPeers int
	MinRatio float64
}

func DefaultThresholds() Thresholds {
	return Thresholds{MinPeers: 3, MinRatio: 0.6}
}

// Finding is an entry point that falls short of an expectation.
type Finding struct {
	Class   string
	CWE     string
	Message string
	Origin  string
	Gates   bool

	EntryPoint  string
	EntryLoc    ir.Loc
	Group       string
	MissingRef  string
	MissingName string
	ControlKind string

	// Inferred findings carry the population as evidence (ADR-006).
	Peers          int
	Conforming     int
	ConformingList []string

	// Declared findings carry the declaration that was violated.
	DeclaredBy     string
	DeclaredReason string
}

// Suppression records an inferred expectation that a declaration overrode. Reported so
// that a declaration's effect is visible rather than silent.
type Suppression struct {
	EntryPoint string
	Missing    string
	DeclaredBy string
	Reason     string
}

// Withheld is an inferred authentication expectation the entry point's own evidence
// answered: the caller presented a secret and the handler resolved a record from it.
//
// The population can only compare an entry point with what its peers MOUNT, and a route
// that authenticates by a bearer-style token mounts nothing -- that is what makes it a
// signing link rather than a session. Comparing the two says "no control here" about a
// route whose control is in its first statement. documenso's five CWE-306 findings were
// all of this shape and an independent reader judged every one false.
//
// Reported rather than silent, and it says which field and which lookup, because the
// judgement is checkable only if the reader can go and look at the line.
type Withheld struct {
	EntryPoint string
	Missing    string
	Field      string
	Selection  string
	Loc        ir.Loc
}

// UnmatchedRule is a declaration that selected no entry point — a stated expectation
// nothing was checked against. Reported because an unchecked requirement is not a
// satisfied one (ADR-003, ADR-011).
type UnmatchedRule struct {
	Match  string
	Reason string
}

// Result is the outcome of the analysis.
type Result struct {
	Applicable          bool
	MissingCapabilities []string
	Thresholds          Thresholds
	PolicyPresent       bool
	PolicyPath          string

	Findings       []Finding
	Suppressed     []Suppression
	Withheld       []Withheld
	UnmatchedRules []UnmatchedRule
}

// Gating reports whether any violated expectation may fail the build.
func (r Result) Gating() bool {
	for _, f := range r.Findings {
		if f.Gates {
			return true
		}
	}
	return false
}

// Analyze evaluates declared expectations first, then inferred ones.
func Analyze(d *ir.IR, s surface.Surface, m model.Model, p *policy.Policy, t Thresholds) Result {
	if missing := m.SurfaceReq.Missing(d.Frontend.Capabilities); len(missing) > 0 {
		return Result{Applicable: false, MissingCapabilities: missing, Thresholds: t}
	}
	if p == nil {
		p = &policy.Policy{}
	}

	res := Result{
		Applicable:    true,
		Thresholds:    t,
		PolicyPresent: p.Present,
		PolicyPath:    p.Path,
	}

	exempt := make(map[string]policy.EntryPointRule)
	matched := make(map[string]bool)

	for _, e := range s.Entries {
		for _, rule := range p.RulesFor(e.Method, e.Path, e.Group) {
			matched[rule.Match.String()] = true

			if rule.PublicByDesign {
				exempt[e.Label()] = rule
			}
			for _, kind := range rule.RequiresControls {
				if hasControlKind(e, kind) {
					continue
				}
				res.Findings = append(res.Findings, Finding{
					Class:  "Declared control missing",
					CWE:    weaknessAt(kind, entryPath(e)),
					Origin: OriginDeclared,
					// A team that stated this expectation gets it enforced.
					Gates: true,
					Message: fmt.Sprintf(
						"policy requires a control of kind %q here; none is applied", kind),
					EntryPoint:     e.Label(),
					EntryLoc:       entryLoc(e),
					Group:          e.Group,
					ControlKind:    kind,
					MissingName:    kind,
					DeclaredBy:     rule.Match.String(),
					DeclaredReason: rule.Reason,
				})
			}
		}
	}

	for _, rule := range p.EntryPoints {
		if !matched[rule.Match.String()] {
			res.UnmatchedRules = append(res.UnmatchedRules, UnmatchedRule{
				Match:  rule.Match.String(),
				Reason: rule.Reason,
			})
		}
	}

	res.appendInferred(s, t, exempt)

	sort.Slice(res.Findings, func(i, j int) bool {
		if res.Findings[i].Origin != res.Findings[j].Origin {
			return res.Findings[i].Origin < res.Findings[j].Origin
		}
		if res.Findings[i].Group != res.Findings[j].Group {
			return res.Findings[i].Group < res.Findings[j].Group
		}
		return res.Findings[i].EntryPoint < res.Findings[j].EntryPoint
	})
	return res
}

// appendInferred adds convention deviations, minus any entry point a declaration says
// is intentionally unprotected.
func (r *Result) appendInferred(s surface.Surface, t Thresholds, exempt map[string]policy.EntryPointRule) {
	groups := s.Groups()

	for _, name := range s.GroupNames() {
		peers := groups[name]
		if len(peers) < t.MinPeers {
			continue
		}

		for _, sig := range expectedSignals(peers, t) {
			for _, e := range peers {
				if _, has := e.ControlRefs()[sig.ref]; has {
					continue
				}
				if !applies(sig.kind, e) {
					continue
				}
				// A declaration that this surface is public by design overrides what
				// its peers imply — and the override is recorded, not silent.
				if rule, ok := exempt[e.Label()]; ok {
					r.Suppressed = append(r.Suppressed, Suppression{
						EntryPoint: e.Label(),
						Missing:    sig.name,
						DeclaredBy: rule.Match.String(),
						Reason:     rule.Reason,
					})
					continue
				}
				// The population says an authentication control is expected around
				// here; this entry point authenticates by a different means, and the
				// inference does not survive that. Recorded rather than dropped, for
				// the same reason a declared exemption is: an inference that goes quiet
				// invisibly is an inference nobody can check.
				if sig.kind == "authentication" && e.Credential != nil {
					r.Withheld = append(r.Withheld, Withheld{
						EntryPoint: e.Label(),
						Missing:    sig.name,
						Field:      e.Credential.Field,
						Selection:  e.Credential.Selection,
						Loc:        e.Credential.Loc,
					})
					continue
				}
				r.Findings = append(r.Findings, Finding{
					Class:          "Inconsistent access control",
					CWE:            weaknessAt(sig.kind, entryPath(e)),
					Origin:         OriginInferred,
					Gates:          false,
					Message:        fmt.Sprintf("%s is not applied here, but is applied by most comparable entry points", sig.name),
					EntryPoint:     e.Label(),
					EntryLoc:       entryLoc(e),
					Group:          name,
					MissingRef:     sig.ref,
					MissingName:    sig.name,
					ControlKind:    sig.kind,
					Peers:          len(peers),
					Conforming:     sig.count,
					ConformingList: sig.conforming,
				})
			}
		}
	}
}

type signal struct {
	ref        string
	name       string
	kind       string
	count      int
	conforming []string
}

func expectedSignals(peers []surface.EntryFacts, t Thresholds) []signal {
	counts := make(map[string]*signal)

	for _, e := range peers {
		for ref, c := range e.ControlRefs() {
			// App-wide bindings apply to every route equally, so they can never
			// produce a deviation.
			if c.Scope == "app" {
				continue
			}
			s, ok := counts[ref]
			if !ok {
				s = &signal{ref: ref, name: c.Name, kind: c.Kind}
				counts[ref] = s
			}
			s.count++
			s.conforming = append(s.conforming, e.Label())
		}
	}

	var out []signal
	for _, s := range counts {
		if s.count == len(peers) {
			continue
		}
		if float64(s.count)/float64(len(peers)) < t.MinRatio {
			continue
		}
		sort.Strings(s.conforming)
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ref < out[j].ref })
	return out
}

func hasControlKind(e surface.EntryFacts, kind string) bool {
	for _, c := range e.Controls {
		if c.Kind == kind {
			return true
		}
	}
	return false
}

func entryLoc(e surface.EntryFacts) ir.Loc { return e.Loc() }

// Fingerprint is an inferred finding's identity across runs.
//
// The taint kind has had one since ADR-014 and this kind has not, and the cost was not
// theoretical: five CWE-306 findings on documenso's tRPC surface were adjudicated FALSE
// and could not be recorded, because the ledger keys on a fingerprint and these carried
// none. A verdict that cannot be written down is a verdict that has to be reached again,
// and precision computed over the findings that CAN be scored reads six points higher
// than precision over the findings the engine actually reported.
//
// Built from what the finding IS, on the same principle as the taint fingerprint: the
// rule that inferred it, the classification, the entry point it is about, the population
// it was compared against, and the control found missing. `EntryLoc` is deliberately
// absent -- an inserted import above a handler must not mint a new defect -- and so is
// the peer COUNT, because one more sibling route arriving does not make this a different
// finding about this entry point.
func (f Finding) Fingerprint() string {
	parts := []string{f.Origin, f.CWE, f.EntryPoint, f.Group, f.MissingName, f.ControlKind}
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:8])
}
