package surface

import (
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
)

// CallerCredential is the evidence that an entry point resolves WHO IS CALLING from a
// secret the caller presented, rather than from a session an authentication middleware
// established.
//
// A signing link, a password-reset link, an email-verification link, an unsubscribe link
// and a webhook callback are all written this way, and every one of them reads as
// unauthenticated to a population comparison, because the population is a comparison
// against session middleware and these routes deliberately have none. documenso measured
// the cost: enumerating its tRPC surface produced five CWE-306 findings and an
// independent reader judged all five false against the source, every one a procedure
// built from the unauthenticated builder that resolves a recipient from the signing
// token the caller sent -- `remove-signed-field-with-token.ts:19` is the whole of it.
//
// The claim is deliberately narrow, and the field names say which half is evidence. The
// engine can see that a value the caller had to POSSESS selected a record, and it does
// not prove the program refuses when that selection finds nothing: that is a fact about
// the callee's control flow and, for four of documenso's five, about a library call's
// own failure mode (`findFirstOrThrow`). What it is used for is correspondingly narrow --
// it withdraws an INFERENCE about a missing control, and never asserts one is present.
//
// Deliberately NOT folded into EntryFacts.Authenticates, which is a different claim used
// for a different purpose. That one lowers the rank of a disclosure by asking who can be
// on the far side of it, and a bearer token is not a session: it travels in links, in
// mail, in browser history and in access logs, so "the caller proved they hold this
// token" is weaker evidence about the audience than "the caller has an account here".
// Keeping them apart also keeps this change's blast radius to the one inference it is
// about.
type CallerCredential struct {
	// Field is the request field the secret arrived in, as the program named it.
	Field string
	// Selection is the record selection keyed by it, as the call was written.
	Selection string
	// Loc is that selection, so the claim can be read rather than believed.
	Loc ir.Loc
}

// callerSources is what the MODEL says a caller-supplied value looks like, harvested once
// so the two questions that need it -- is this function a request handler, and is this
// value the credential the caller presented -- cannot drift apart on the answer.
type callerSources struct {
	// kinds are the value kinds a frontend marks as caller-supplied outright: an
	// injected NestJS parameter, a tRPC handler's `input`.
	kinds map[string]bool
	// globals are the framework request objects reached as a module-level name,
	// `flask.request` and its kin.
	globals map[string]bool
	// pathsAt are the paths a request object exposes -- "body", "query", "params" --
	// kept under the PARAMETER POSITION the rule names them at.
	//
	// The position is part of the rule and dropping it is what made the completeness
	// count unusable. Flattened into one set matched against ANY parameter, the union of
	// every framework's request shape matches an enormous amount of code that is not a
	// handler at all: searxng's engine plugins take an outbound `params` dict as their
	// SECOND argument and set params["headers"], and 62 of them counted as unreached
	// request handlers.
	pathsAt map[int]map[string]bool
}

func newCallerSources(m model.Model) callerSources {
	src := callerSources{
		kinds:   map[string]bool{},
		globals: map[string]bool{},
		pathsAt: map[int]map[string]bool{},
	}
	for _, c := range m.Classifications {
		if c.Class != m.UntrustedClass() {
			continue
		}
		for _, r := range c.Rules {
			// A source only a person with a shell can supply is neither evidence that a
			// route was missed nor a credential a remote caller presented.
			if r.Trust != "" && r.Trust != ir.Remote {
				continue
			}
			switch r.Match {
			case model.MatchValueKind:
				src.kinds[r.ValueKind] = true
			case model.MatchGlobalProperty:
				src.globals[r.Symbol] = true
			case model.MatchEntryParamProperty:
				if src.pathsAt[r.ParamIndex] == nil {
					src.pathsAt[r.ParamIndex] = map[string]bool{}
				}
				for _, p := range r.Paths {
					src.pathsAt[r.ParamIndex][p] = true
				}
			}
		}
	}
	return src
}

// credentialOf answers EntryFacts.Credential: did this entry point resolve a record from
// a secret the caller presented.
//
// Two facts joined, and neither is worth anything alone. A value the caller sent whose
// own name says it is a secret is just a string; a record selected by a value the caller
// sent is, on its own, precisely the shape of an insecure direct object reference. What
// separates the two is whether the caller could have GUESSED the value, and the program
// answers that itself in the name it gave the field: `token`, `secret`, `apiKey` name
// something unguessable by design, and `documentId`, `fieldId` and `slug` name something
// a caller can count through.
//
// The walk stops one hop below the handler, the same bound and for the same reason as
// authenticatesCaller: documenso's routes hand the token straight to a server-only
// function that performs the lookup on its first line, and stopping at the handler would
// miss four of the five. Two hops reaches every helper the application owns.
func credentialOf(ix *ir.Index, fn *ir.Function, m model.Model, src callerSources) *CallerCredential {
	if fn == nil {
		return nil
	}
	seeds := secretsPresentedTo(ix, fn, m, src)
	if len(seeds) == 0 {
		return nil
	}
	here := carriersOf(fn)
	// The handler's own lookup first, so the line a report cites is the nearest one a
	// reader can go and check. `completeDocumentWithToken` is documenso's one route
	// written that way; the other four hand the token down.
	for _, seed := range seeds {
		if c := selectsRecord(fn, m, here.spread(seed.value)); c != nil {
			return &CallerCredential{Field: seed.field, Selection: calleeSpelling(c), Loc: c.Loc}
		}
	}
	below := map[string]*carriers{}
	for _, seed := range seeds {
		carried := here.spread(seed.value)
		for _, call := range fn.Calls {
			callee := ix.FuncByID[call.Callee.FunctionID]
			if callee == nil || callee.ID == fn.ID {
				continue
			}
			bound := boundBelow(call, callee, carried)
			if len(bound) == 0 {
				continue
			}
			if below[callee.ID] == nil {
				below[callee.ID] = carriersOf(callee)
			}
			for _, param := range bound {
				if c := selectsRecord(callee, m, below[callee.ID].spread(param)); c != nil {
					return &CallerCredential{Field: seed.field, Selection: calleeSpelling(c), Loc: c.Loc}
				}
			}
		}
	}
	return nil
}

// secret is one caller-supplied value whose own name says it holds one.
type secret struct {
	value string
	field string
}

// secretsPresentedTo collects the values in this handler that the caller supplied AND
// whose leaf name says they hold a secret, in source order so that a report citing one of
// them cites the same one on every run.
func secretsPresentedTo(ix *ir.Index, fn *ir.Function, m model.Model, src callerSources) []secret {
	params := make(map[string]ir.Param, len(fn.Params))
	for i, p := range fn.Params {
		// A parameter's position is its place in this list for an ordinary parameter and
		// is not for a destructured one, where every bound name sits at the position of
		// the single argument it takes apart.
		if !p.Destructured {
			p.Index = i
		}
		params[p.ValueID] = p
	}
	var out []secret
	for _, v := range fn.Values {
		// A parameter a framework fills from the request directly -- `@Param('token')
		// token`, a tRPC handler's `input` -- IS the value, with no property to read.
		if src.kinds[string(v.Kind)] {
			if leaf := lastSegment(namePath(v)); m.NamesSecretField(leaf) {
				out = append(out, secret{value: v.ID, field: leaf})
			}
			continue
		}
		if v.Kind != ir.ValueProperty {
			continue
		}
		leaf := lastSegment(v.Path)
		if !m.NamesSecretField(leaf) {
			continue
		}
		base := ix.ValueByID[v.Base]
		if base == nil {
			continue
		}
		switch {
		// `input.token` on a tRPC handler, `body.password` on an injected NestJS body.
		case src.kinds[string(base.Kind)]:
			out = append(out, secret{value: v.ID, field: leaf})
		// `flask.request.form.password`.
		case base.Kind == "global" && src.globals[base.Name]:
			out = append(out, secret{value: v.ID, field: leaf})
		default:
			// `req.query.token`, where the rule is about a path at a parameter POSITION.
			p, ok := params[v.Base]
			if !ok {
				continue
			}
			path := v.Path
			if p.Destructured && p.Path != "" {
				path = p.Path + "." + v.Path
			}
			if src.pathsAt[p.Index][firstSegment(path)] {
				out = append(out, secret{value: v.ID, field: leaf})
			}
		}
	}
	return out
}

// carriers is the shape of one function's values: which value each one is filed INTO, and
// under which key.
//
// Built once per function rather than once per question: a handler that reads two secrets
// and makes forty calls would otherwise walk its own value list eighty times.
type carriers struct {
	// enclosing maps a value to the object literals holding it, with the key it sits
	// under at each one.
	enclosing map[string][]carrier
	// assigns maps a value to the values it was assigned to, which is how a secret
	// survives being given a local name.
	assigns map[string][]string
}

type carrier struct {
	key   string
	value string
}

func carriersOf(fn *ir.Function) *carriers {
	c := &carriers{enclosing: map[string][]carrier{}, assigns: map[string][]string{}}
	for _, v := range fn.Values {
		for _, e := range v.Entries {
			if e.ValueID == "" {
				continue
			}
			c.enclosing[e.ValueID] = append(c.enclosing[e.ValueID], carrier{key: e.Key, value: v.ID})
		}
	}
	for _, f := range fn.Flows {
		if f.Kind == "assign" {
			c.assigns[f.From] = append(c.assigns[f.From], f.To)
		}
	}
	return c
}

// spread walks a value outward and reports every value that CARRIES it, with the key it
// sits under at the TOP LEVEL of that carrier.
//
// The top-level key is the only part a callee binding needs, and taking it there is what
// keeps the binding honest about depth: `f({ token })` hands the callee's `{ token }`
// binding a secret, while `f({ opts: { token } })` hands `opts` an object that contains
// one -- and below that binding only a use of the object WHOLE carries the secret on,
// because a property read is not an enclosure and is not followed. An empty key means the
// value IS this one, by identity or by assignment.
func (c *carriers) spread(seed string) map[string]string {
	out := map[string]string{seed: ""}
	queue := []string{seed}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range c.enclosing[cur] {
			if _, seen := out[e.value]; seen {
				continue
			}
			out[e.value] = e.key
			queue = append(queue, e.value)
		}
		for _, to := range c.assigns[cur] {
			if _, seen := out[to]; seen {
				continue
			}
			out[to] = out[cur]
			queue = append(queue, to)
		}
	}
	return out
}

// selectsRecord returns the store READ this function performs with the carried value, if
// it performs one.
//
// A read only, and the model already says why one argument position is as good as
// another here: "a read has no value argument: everything a read is handed is criteria"
// (model.StoreAccess.ValueArg). So a secret anywhere in what the read was handed is a
// secret the row was selected by.
func selectsRecord(fn *ir.Function, m model.Model, carried map[string]string) *ir.Call {
	for _, c := range fn.Calls {
		if _, ok := m.StoreReadAt(c.Callee.Symbol, c.Method, c.ReceiverType); !ok {
			continue
		}
		for _, a := range c.Args {
			if a.ValueID == "" {
				continue
			}
			if _, ok := carried[a.ValueID]; ok {
				return c
			}
		}
	}
	return nil
}

// boundBelow is every parameter of the callee that this call hands the carried secret to.
//
// By name AND by position. Position was excluded here once, and the reason was real: a
// positional index did not survive a receiver, because Python declares `self` and `cls`
// as parameter zero and writes neither at the call site, so
// `cls._set_password_for_user(email, password, token)` bound its second argument to the
// callee's `email`. saleor's `setPassword` came out citing `User.objects.get(email=email)`
// as a selection keyed by the caller's PASSWORD, when the row is selected by the email
// and the token is checked by a generator two statements later. The route does
// authenticate by token; the sentence the engine wrote about it was false.
//
// The frontend now states which parameter each written argument becomes (ir.Arg.
// ParamIndex), so the index means what it says and the exclusion is no longer paying for
// anything. Restoring it recovers the miss the exclusion recorded -- a secret handed down
// as a bare positional argument, `recipientByToken(token)` -- and, measured across the ten
// repositories in the corpus, changes no finding.
func boundBelow(call *ir.Call, callee *ir.Function, carried map[string]string) []string {
	var out []string
	for _, a := range call.Args {
		if a.ValueID == "" {
			continue
		}
		key, ok := carried[a.ValueID]
		if !ok {
			continue
		}
		if key == "" {
			// The argument IS the secret: a keyword names the parameter it fills, and a
			// position now identifies one too.
			if p, found := a.BoundParam(callee); found {
				out = append(out, p.ValueID)
			}
			continue
		}
		// The argument is an options object with the secret filed under one key, which
		// is how every one of documenso's five is written. Only a binding that names
		// that key receives the secret; a callee taking the object whole receives an
		// object, and following it there would say a lookup keyed by any field of that
		// object was keyed by this one.
		for _, p := range a.BoundParams(callee) {
			if p.Destructured && p.Path == key {
				out = append(out, p.ValueID)
			}
		}
	}
	return out
}

// calleeSpelling is how a call was written, for citing it.
func calleeSpelling(c *ir.Call) string {
	if c.Callee.Symbol != "" {
		return c.Callee.Symbol
	}
	if c.Method != "" {
		return c.Method
	}
	return c.Callee.Name
}

// namePath is how a value names itself: its access path when it has one, otherwise the
// name it was bound under.
func namePath(v *ir.Value) string {
	if v.Path != "" {
		return v.Path
	}
	return v.Name
}

// lastSegment is the trailing name of a dotted access path: "body.user.apiKey" -> "apiKey".
func lastSegment(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[i+1:]
		}
	}
	return path
}
