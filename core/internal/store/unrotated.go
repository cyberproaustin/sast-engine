package store

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// unrotatedOnUpdate reads one store call that says BOTH what to write when a record is
// new and what to write when it already exists, and reports when the new-record half
// mints a credential that the existing-record half rewrites the subject without.
//
// The weakness is that a credential is not bound to what it admits. healthchecks' fixed
// email-verification token is the shape: the token was seeded with the channel's
// immutable id and the server secret and not with the address, so changing the address
// left the token standing and the old link verified the new one. documenso writes the
// same defect in TypeScript, in one expression:
//
//	tx.recipient.upsert({
//	  where:  { id, envelopeId },
//	  update: { name, email, role },                 // the address changes
//	  create: { name, email, role, token: nanoid() } // and this does not
//	})
//
// What makes this sayable without a population is that the program answers the question
// itself. An absence rule normally has to argue that a missing field OUGHT to be there --
// the reason CWE-384's convention form was withdrawn -- and here the create half is the
// argument: this application's own statement of what a new record of this kind needs.
// Nothing outside the call is read.
//
// Measured over ten production repositories: TWO calls match, documenso's
// `set-document-recipients.ts:155` and `set-template-recipients.ts:136`, and both are the
// weakness. The broader shape this was reshaped FROM -- a create somewhere in the program
// naming a credential and an update elsewhere not naming it -- matches 173 times over the
// same corpus, which is what an absence rule looks like when the program has not been
// asked to state its own convention.
func unrotatedOnUpdate(ix *ir.Index, m model.Model, fn *ir.Function, c *ir.Call, rule model.StoreRule) (taint.Finding, bool) {
	access, ok := m.StoreWriteAt(c.Callee.Symbol, c.Method, c.ReceiverType)
	if !ok {
		return taint.Finding{}, false
	}
	// An absence is only knowable where the keys were read in full. A call whose options
	// were assembled elsewhere sets fields this cannot see, and "the update does not
	// rotate the token" would then be a claim about the frontend (ADR-003).
	if !c.OptionsEnumerated(-1) && !c.OptionsEnumerated(0) {
		return taint.Finding{}, false
	}
	groups := access.WrittenGroups(c.ArgLiterals)
	insert := fieldsIn(groups, rule.OnInsert)
	update := fieldsIn(groups, rule.OnUpdate)
	if len(insert) == 0 || len(update) == 0 {
		return taint.Finding{}, false
	}
	// Sorted, so a call minting two credentials cites the same one on every run.
	credential := ""
	for _, field := range sortedKeys(insert) {
		if m.NamesSecretField(field) && !update[field] {
			credential = field
			break
		}
	}
	if credential == "" {
		return taint.Finding{}, false
	}
	// The subject is what the credential admits. An update that rewrites a status or a
	// sort order leaves the credential pointing at the same person, and rotating it there
	// would be a nuisance rather than a fix.
	subject := ""
	for _, want := range rule.SubjectFields {
		if update[model.NormalizeFieldName(want)] {
			subject = want
			break
		}
	}
	if subject == "" {
		return taint.Finding{}, false
	}
	return unrotatedFinding(ix, fn, c, rule, access, credential, subject), true
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// fieldsIn collects the columns written under any of these option groups.
func fieldsIn(groups map[string][]string, names []string) map[string]bool {
	out := map[string]bool{}
	for _, name := range names {
		for _, field := range groups[strings.ToLower(name)] {
			out[field] = true
		}
	}
	return out
}

func unrotatedFinding(ix *ir.Index, fn *ir.Function, c *ir.Call, rule model.StoreRule,
	access model.StoreAccess, credential, subject string) taint.Finding {
	name := c.Callee.Symbol
	if name == "" {
		name = c.Method
	}
	record := access.StoreName(c.Callee.Symbol, c.Method)
	if record == "" {
		record = "record"
	}
	f := taint.Finding{
		Analysis:     rule.ID,
		ChannelID:    rule.ID,
		Class:        rule.Finding,
		CWE:          rule.CWE,
		Message:      rule.Reason,
		Confidence:   taint.High,
		SourceLabel:  name,
		InTestModule: ix.InTestModule(c.Loc),
		SourceLoc:    c.Loc,
		SinkLoc:      c.Loc,
		SinkFunction: fn.Name,
		SinkSymbol:   name,
		SinkArgIndex: -1,
		SinkRational: fmt.Sprintf("%s; the new-record half of this %s mints %s and the existing-record half rewrites %s without it",
			rule.Rationale, record, credential, subject),
		Path: []taint.Hop{{
			Loc:         c.Loc,
			Description: fmt.Sprintf("%s() writes %s only when the %s is new", name, credential, record),
			Resolution:  c.Callee.Resolution,
		}},
	}
	if ep, ok := taint.EntryOf(ix, fn); ok {
		f.EntryPoint = taint.EntryLabel(*ep)
		f.EntryMethod = ep.Detail["method"]
		f.EntryPath = ep.Detail["path"]
		f.EntryAnchored = true
		f.EntryTrust = ep.TrustLevel()
	}
	return f
}
