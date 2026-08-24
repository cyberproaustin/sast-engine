// Package policy loads what a team has declared about its own application.
//
// Everything here is a statement of FACT about the system — this route is public by
// design, this surface requires authorization — never a statement about findings
// (ADR-013). There is deliberately no way to express "ignore this result": a team that
// wants output to stop must say what makes it wrong, and that statement then covers
// every future instance of the same property.
//
// Declared expectations are the only ones that gate a build (ADR-011). Inference can
// inform; only a team that wrote down what it expects has earned an enforceable claim.
package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// SupportedVersion is the policy schema version this core understands.
const SupportedVersion = 1

// Match selects entry points by property. Matching on a property rather than on an
// identifier is what makes a declaration apply to routes that do not exist yet.
type Match struct {
	PathPrefix string `json:"pathPrefix,omitempty"`
	Group      string `json:"group,omitempty"`
	Method     string `json:"method,omitempty"`
}

// Empty reports whether this match selects nothing.
func (m Match) Empty() bool {
	return m.PathPrefix == "" && m.Group == "" && m.Method == ""
}

func (m Match) String() string {
	var parts []string
	if m.Method != "" {
		parts = append(parts, m.Method)
	}
	if m.PathPrefix != "" {
		parts = append(parts, m.PathPrefix+"*")
	}
	if m.Group != "" {
		parts = append(parts, "in "+m.Group)
	}
	if len(parts) == 0 {
		return "<matches nothing>"
	}
	return strings.Join(parts, " ")
}

// EntryPointRule is one declaration about a set of entry points.
type EntryPointRule struct {
	Match Match `json:"match"`

	// PublicByDesign states that reaching this surface without authentication is
	// intended. It suppresses inferred expectations about authentication — and the
	// suppression is reported, never silent.
	PublicByDesign bool `json:"publicByDesign,omitempty"`

	// RequiresControls states that these control kinds must be present. A violation
	// is a DECLARED finding and gates the build.
	RequiresControls []string `json:"requiresControls,omitempty"`

	// EstablishesIdentity states that this entry point's purpose is to establish who
	// the caller is — login, registration, password reset. Judgements that presuppose
	// an existing actor do not apply, because there is not one yet. Code cannot tell
	// this apart from an unauthenticated data endpoint, which is why it is declared.
	EstablishesIdentity bool `json:"establishesIdentity,omitempty"`

	// Reason is required for anything that relaxes or tightens behavior: a
	// declaration without a stated rationale is a waiver wearing a fact's clothing.
	Reason string `json:"reason"`
}

// ControlDeclaration states what one of the team's own middleware bindings is.
//
// Whether `auth.required` performs authentication is not derivable from the name, and
// guessing from spelling is the failure mode this project exists to avoid (ADR-011).
// The team knows; convention analysis never needed the answer, but a declared
// requirement stated in terms of a control KIND does.
type ControlDeclaration struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

// Policy is a loaded declaration set.
type Policy struct {
	Version     int                  `json:"version"`
	Controls    []ControlDeclaration `json:"controls,omitempty"`
	EntryPoints []EntryPointRule     `json:"entryPoints,omitempty"`

	// Path is where this was loaded from, for reporting. Empty means none was
	// supplied, which is a distinct state from an empty policy.
	Path    string `json:"-"`
	Present bool   `json:"-"`
}

// Load reads a policy document.
func Load(r io.Reader, path string) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(r)
	// Unknown fields are rejected rather than ignored, so that ADR-013 is enforced by
	// the loader and not merely documented: someone adding an `ignore` or
	// `suppressions` key gets an error instead of a silent no-op.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w (declarations state facts about the "+
			"application; findings cannot be suppressed — see ADR-013)", path, err)
	}
	if p.Version != SupportedVersion {
		return nil, fmt.Errorf("policy %s declares version %d; this core implements %d",
			path, p.Version, SupportedVersion)
	}
	for i, rule := range p.EntryPoints {
		if rule.Match.Empty() {
			return nil, fmt.Errorf("policy %s: entryPoints[%d] matches nothing", path, i)
		}
		if strings.TrimSpace(rule.Reason) == "" {
			return nil, fmt.Errorf(
				"policy %s: entryPoints[%d] (%s) has no reason; a declaration without a "+
					"rationale is a waiver, and waivers are not expressible (ADR-013)",
				path, i, rule.Match)
		}
	}
	for i, c := range p.Controls {
		if c.Name == "" || c.Kind == "" {
			return nil, fmt.Errorf("policy %s: controls[%d] needs a name and a kind", path, i)
		}
		if strings.TrimSpace(c.Reason) == "" {
			return nil, fmt.Errorf(
				"policy %s: controls[%d] (%s) has no reason; a declaration without a "+
					"rationale is a waiver (ADR-013)", path, i, c.Name)
		}
	}
	p.Path = path
	p.Present = true
	return &p, nil
}

// LoadFile reads a policy from disk. A missing file is not an error — it means the team
// has declared nothing, which the report states explicitly.
func LoadFile(path string) (*Policy, error) {
	if path == "" {
		return &Policy{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Policy{}, nil
		}
		return nil, fmt.Errorf("open policy: %w", err)
	}
	defer f.Close()
	return Load(f, path)
}

// ClassifyControl returns the declared kind for a control name, or "".
func (p *Policy) ClassifyControl(name string) string {
	if p == nil {
		return ""
	}
	for _, c := range p.Controls {
		if c.Name == name {
			return c.Kind
		}
	}
	return ""
}

// Declares reports whether this rule asserts a named property of the application.
// Policies name the property that exempts them, so a new declaration is a data change
// rather than a special case in the engine.
func (r EntryPointRule) Declares(property string) bool {
	switch property {
	case "publicByDesign":
		return r.PublicByDesign
	case "establishesIdentity":
		return r.EstablishesIdentity
	}
	return false
}

// Matches reports whether a rule selects an entry point with these properties.
func (r EntryPointRule) Matches(method, path, group string) bool {
	if r.Match.Method != "" && !strings.EqualFold(r.Match.Method, method) {
		return false
	}
	if r.Match.PathPrefix != "" && !strings.HasPrefix(path, r.Match.PathPrefix) {
		return false
	}
	if r.Match.Group != "" && r.Match.Group != group {
		return false
	}
	return true
}

// RulesFor returns every declaration selecting an entry point.
func (p *Policy) RulesFor(method, path, group string) []EntryPointRule {
	var out []EntryPointRule
	for _, r := range p.EntryPoints {
		if r.Matches(method, path, group) {
			out = append(out, r)
		}
	}
	return out
}
