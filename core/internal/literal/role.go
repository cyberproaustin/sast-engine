package literal

import (
	"fmt"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
)

// The role judgement: does THIS program rely on the value being secret?
//
// A value-shape rule can say that a run of characters is the shape a provider issues
// credentials in. It cannot say whose credential it is, and across ten production
// repositories that gap was the single largest source of false findings left: 27 of 56,
// every one of them a public client identifier in yt-dlp. A Firebase web API key sent as
// the `key` query parameter of an Identity Toolkit sign-in, a Google Drive playback key
// sent with a `drive.google.com` Referer, an Adobe `software_statement` posted to a
// client-registration endpoint. yt-dlp is a client of every site it has an extractor for.
// There is no server in that program whose door any of those keys opens.
//
// So the shape classifies and the USE decides, exactly as the weak-digest rule now works.
// Two roles, and only two:
//
//	PRESENTED   the program hands the value to somebody else's service to say which
//	            client it is. It travels outward under a request part -- a query
//	            parameter, a header, a body field -- and nothing here rests on nobody
//	            else having read it. That is the third party's public configuration.
//
//	RELIED UPON the program compares a caller's value against it, signs with it, admits
//	            a caller by it, or files it under a request part whose own name says it
//	            is a credential. Then this program's security IS the value's secrecy.
//
// Relied-upon always wins. Where neither is visible the value is reported, because a key
// written into a repository is in every clone of it whether or not this scan could see
// what reads it -- a private key block in a constant nothing calls is still a leak, and
// the shape rules exist for exactly that case.

// roleNodeBudget caps one walk. The longest real chain in the corpus visits fewer than a
// hundred values; anything beyond this is fan-out through a container, and fan-out
// answers a question about the container rather than about the value.
const roleNodeBudget = 400

// role is what the program does with a written-down value.
type role int

const (
	roleUndecided role = iota
	// rolePresented: handed outward to name this program as somebody's client.
	rolePresented
	// roleRelied: this program's own security rests on it.
	roleRelied
)

// roleFinder answers the question for one literal at a time, over a bounded neighbourhood
// of the value. Built once per scan because the name index is program-wide.
type roleFinder struct {
	ix    *ir.Index
	rule  model.ClientRoleRule
	built bool

	// readsOfName maps a name bound at module or class scope to every place the program
	// reads it. A credential written into a class attribute is used three files away --
	// `_SOFTWARE_STATEMENT`, `_LOGIN_QUERY`, `_SITE_INFO` -- and without this the role of
	// twenty-one of yt-dlp's twenty-seven is simply not visible.
	readsOfName map[string][]site
	// funcsByName resolves a call the frontend could only name. `self._extract_mvpd_auth`
	// lowers as an unresolved external symbol because the method is defined in another
	// module's class, and the parameter it lands on is where the request is made. Only a
	// name with exactly one definition in the program is followed; an ambiguous name is
	// not guessed at.
	funcsByName map[string][]*ir.Function
	// valuesByBase finds the values read back OUT of a container, which is how a token
	// buried in a nested constant reaches the call that sends it.
	valuesByBase map[string][]site
	// keyArgSymbols are the calls whose argument at an index IS a key, taken from the
	// call-shape rules that already report a hardcoded one. A value handed to one of
	// these is a key by the program's own admission.
	keyArgSymbols map[string]bool
}

type site struct {
	fn *ir.Function
	v  *ir.Value
}

func newRoleFinder(ix *ir.Index, m model.Model) *roleFinder {
	f := &roleFinder{ix: ix, rule: m.ClientRole}
	f.keyArgSymbols = make(map[string]bool)
	for _, s := range m.CallShapes {
		if s.CWE == "CWE-798" && s.Symbol != "" {
			f.keyArgSymbols[strings.ToLower(s.Symbol)] = true
		}
	}
	return f
}

// index is built on first use. A scan of a program with no credential-shaped literal in
// it pays nothing for this.
func (f *roleFinder) index() {
	if f.built {
		return
	}
	f.built = true
	f.readsOfName = make(map[string][]site)
	f.funcsByName = make(map[string][]*ir.Function)
	f.valuesByBase = make(map[string][]site)
	for _, fn := range f.ix.IR.Functions {
		if fn.Name != "" {
			f.funcsByName[fn.Name] = append(f.funcsByName[fn.Name], fn)
		}
		for _, v := range fn.Values {
			if v.Base != "" {
				f.valuesByBase[v.Base] = append(f.valuesByBase[v.Base], site{fn, v})
			}
			// A read of a name bound elsewhere: `self._API_KEY` is a property whose
			// path is the attribute, and a bare module-level constant is a global.
			switch v.Kind {
			case ir.ValueProperty:
				if bindable(v.Path) {
					f.readsOfName[v.Path] = append(f.readsOfName[v.Path], site{fn, v})
				}
			case ir.ValueGlobal:
				if bindable(v.Name) {
					f.readsOfName[v.Name] = append(f.readsOfName[v.Name], site{fn, v})
				}
			}
		}
	}
}

// bindable rejects the names the frontends invent for things that have none. A dict
// literal, a sequence and an f-string are values the program built, not names it bound,
// and joining two functions on one of those would join every function in the program.
func bindable(name string) bool {
	if len(name) < 3 || len(name) > 64 {
		return false
	}
	if strings.ContainsAny(name, "{}[]<>() .") {
		return false
	}
	switch strings.ToLower(name) {
	case "self", "cls", "this", "local", "unresolved", "none", "null", "undefined":
		return false
	}
	return true
}

// moduleScope reports whether a function is a module or class BODY rather than a
// procedure -- the place a program binds its constants. Both frontends lower top-level
// and class-level statements into a function of this name.
func moduleScope(fn *ir.Function) bool {
	return fn.Name == "<module>" || fn.Name == "<toplevel>"
}

// readsOf returns the places a name bound in one module is read.
//
// A name is resolved in the module that binds it. Only where NOTHING in that module reads
// it does the engine look further, and then it takes every read of the name in the
// program -- which is how a constant on a base class reaches the subclass that uses it,
// `_LOGIN_QUERY` bound in stacommu.py and read in wrestleuniverse.py.
//
// The narrowing is not tidiness. `_API_KEY` names seven unrelated constants in seven
// yt-dlp extractors, and joining all seven made one extractor's Authorization header
// speak for another extractor's query parameter.
func (f *roleFinder) readsOf(name, module string) []site {
	all := f.readsOfName[name]
	var local []site
	for _, s := range all {
		if s.fn.Module == module {
			local = append(local, s)
		}
	}
	if len(local) > 0 {
		return local
	}
	return all
}

// classify walks out from one written-down value and reports what the program does with
// it. The walk is bounded by the model's budget: a role is decided from a neighbourhood
// of the literal or it is not decided at all.
func (f *roleFinder) classify(fn *ir.Function, v *ir.Value, text string) (role, string) {
	if len(f.rule.RequestParts) == 0 {
		return roleUndecided, ""
	}
	f.index()

	type step struct {
		fn    *ir.Function
		id    string
		depth int
		// crossed counts the function boundaries the walk has passed. It gates one
		// judgement only: whether an option whose NAME says "credential" but whose value
		// was not written down can be taken to be carrying this value. Inside the
		// function that reads the value, it can -- `headers={'Authorization': f'Bearer
		// {KEY}'}` writes the option and the value in one breath. Two functions away it
		// cannot: adobepass sets an Authorization header from an access token it fetched
		// itself, and reading that as evidence about a software statement passing through
		// the same function reported eight literals that the program never treats as
		// secrets.
		crossed int
	}
	seen := map[string]bool{}
	queue := []step{{fn, v.ID, 0, 0}}
	presented := ""

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.fn == nil || seen[cur.id] || cur.depth > f.rule.Budget || cur.crossed > 2 {
			continue
		}
		seen[cur.id] = true
		// A walk that has visited this many values is not deciding a role any more, it
		// is touring the program. Whatever it has found by now is the answer.
		if len(seen) > roleNodeBudget {
			break
		}

		// What the calls in this function do with the value.
		for _, c := range cur.fn.Calls {
			// `json.dumps(payload).encode()` puts the value in the receiver position of
			// the second call, and a walk that only reads arguments stops there -- one
			// step short of the request.
			if c.ReceiverID == cur.id && c.ResultID != "" && f.rule.IsCarrier(c.Callee.Symbol, c.Method) {
				queue = append(queue, step{cur.fn, c.ResultID, cur.depth + 1, cur.crossed})
			}
			arg, ok, unique := argumentOf(c, cur.id)
			if !ok {
				continue
			}
			switch r, ev := f.atCall(c, text, cur.crossed == 0); r {
			case roleRelied:
				return roleRelied, ev
			case rolePresented:
				if presented == "" {
					presented = ev
				}
			}
			if f.keyArgSymbols[strings.ToLower(c.Callee.Symbol)] {
				return roleRelied, fmt.Sprintf("handed to %s, where the argument is a key", c.Callee.Symbol)
			}
			// A serializer or an encoder returns the same value in a different
			// container. Without this the walk stops at `json.dumps(...)` and never
			// sees the request two lines later.
			if c.ResultID != "" && f.rule.IsCarrier(c.Callee.Symbol, c.Method) {
				queue = append(queue, step{cur.fn, c.ResultID, cur.depth + 1, cur.crossed})
			}
			// Into the callee, at the parameter this argument binds to. Only for an
			// argument whose binding is unambiguous.
			if unique {
				if callee, pv := f.calleeParam(c, arg); callee != nil && pv != "" {
					queue = append(queue, step{callee, pv, cur.depth + 1, cur.crossed + 1})
				}
			}
		}

		// A comparison is deliberately NOT read here. "The program admits a caller by
		// comparing something against this literal" is a real reliance and it has its
		// own rule -- `credential-admits-caller`, which reads the comparison directly
		// and knows whose value is on the other side. Read from inside this walk it
		// says nothing: the walk crosses containers and library helpers, and a
		// comparison eight hops away in a traversal utility decided the role of five
		// constants in go.py before this was taken out.

		// Forward through the dataflow, and out through any name the value is bound to.
		//
		// The owner of the TARGET is taken from the index rather than assumed to be this
		// function. A module-level constant is resolved by the frontends to the value
		// that defines it, so the edge from `FIREBASE_WEB_KEY` into the f-string that
		// builds a request line is recorded in the function that reads it and points at
		// a value in the module body -- and a walk that kept the module as the owner
		// looked for the request among the module's calls, where there are none.
		for _, fl := range f.ix.FlowsFrom[cur.id] {
			to := f.ix.ValueByID[fl.To]
			if to == nil {
				continue
			}
			owner := f.ix.OwnerOfValue[fl.To]
			if owner == nil {
				owner = cur.fn
			}
			// A string built from this value and an address is a request to that
			// address: `f'https://identitytoolkit.googleapis.com/...?key={KEY}'`.
			if ev, ok := f.builtWithAnAddress(owner, to, text); ok && presented == "" {
				presented = ev
			}
			queue = append(queue, step{owner, fl.To, cur.depth, cur.crossed})
			// Out through a name, but ONLY a name bound at module or class scope.
			//
			// A constant is the case this exists for: twenty-one of yt-dlp's
			// twenty-seven are class attributes whose use is in another file. A LOCAL
			// name is not that, and joining on one joins every function that happens to
			// use the word: with locals included, the walk out of `_SITE_INFO` reached
			// `brand`, then `title`, then half the extractors in the program, and a
			// comparison in bilibili.py decided the role of a constant in go.py.
			if moduleScope(cur.fn) && to.Name != "" && bindable(to.Name) {
				for _, s := range f.readsOf(to.Name, cur.fn.Module) {
					queue = append(queue, step{s.fn, s.v.ID, cur.depth + 1, cur.crossed})
				}
			}
		}

		// Read back out of a container the value was put into: `self._SITE_INFO[site]`
		// and then `site_info['software_statement']`.
		for _, s := range f.valuesByBase[cur.id] {
			queue = append(queue, step{s.fn, s.v.ID, cur.depth, cur.crossed})
		}
	}
	if presented != "" {
		return rolePresented, presented
	}
	return roleUndecided, ""
}

// atCall reads one call site for what it says about a value it was handed.
func (f *roleFinder) atCall(c *ir.Call, text string, atTheValue bool) (role, string) {
	// The option keys the frontend flattened. `query.key=AIza...` says both that the
	// value is in the request and which parameter it is.
	for i, lit := range c.ArgLiterals {
		if i >= 0 {
			continue
		}
		key, value, cut := strings.Cut(lit, "=")
		if !cut {
			continue
		}
		mine := value == text
		if f.rule.NamesASecret(key) && (mine || (atTheValue && value == ir.UnknownLiteral)) {
			return roleRelied, fmt.Sprintf("filed under %q, which names a credential rather than a client", key)
		}
		if mine && f.rule.IsRequestPart(key) {
			return rolePresented, fmt.Sprintf("sent as %q of a request this program makes", key)
		}
	}
	// The service named on the same line. A call carrying an absolute URL written into
	// the source is a call to that address, and a value handed to it goes there.
	for i, lit := range c.ArgLiterals {
		if lit == text {
			continue // our own value, when the value IS the address
		}
		if f.rule.IsURL(lit) {
			if i < 0 {
				if _, v, cut := strings.Cut(lit, "="); cut && v == text {
					continue
				}
			}
			return rolePresented, fmt.Sprintf("handed to a request addressed to %s", elide(urlPart(lit)))
		}
	}
	return roleUndecided, ""
}

// builtWithAnAddress reports whether a value this one flows into is a string that also
// carries an absolute URL written in the source. That is a request line being assembled,
// and the value is one of its parameters.
func (f *roleFinder) builtWithAnAddress(fn *ir.Function, to *ir.Value, text string) (string, bool) {
	for _, in := range fn.Flows {
		if in.To != to.ID {
			continue
		}
		other := f.ix.ValueByID[in.From]
		if other == nil || other.Kind != ir.ValueLiteral || other.Literal == text {
			continue
		}
		if f.rule.IsURL(other.Literal) {
			return fmt.Sprintf("built into a request line addressed to %s", elide(urlPart(other.Literal))), true
		}
	}
	return "", false
}

// calleeParam resolves a call to a function in this program and returns the parameter the
// argument at idx binds to.
//
// A method written on `self` lowers as an unresolved external symbol, because the class
// that defines it is in another module. Resolving it by NAME is how the walk reaches
// `_extract_mvpd_auth`, and it is done only where the name has exactly one definition in
// the whole program: an ambiguous name is left unresolved rather than guessed at.
func (f *roleFinder) calleeParam(c *ir.Call, arg ir.Arg) (*ir.Function, string) {
	var callee *ir.Function
	if c.Callee.Kind == "local" && c.Callee.FunctionID != "" {
		callee = f.ix.FuncByID[c.Callee.FunctionID]
	} else {
		name := c.Method
		if name == "" {
			name = c.Callee.Symbol
			if i := strings.LastIndex(name, "."); i >= 0 {
				name = name[i+1:]
			}
		}
		if name == "" {
			return nil, ""
		}
		if fns := f.funcsByName[name]; len(fns) == 1 {
			callee = fns[0]
		}
	}
	if callee == nil || len(callee.Params) == 0 {
		return nil, ""
	}
	if arg.Name != "" {
		if p, ok := arg.BoundParam(callee); ok {
			return callee, p.ValueID
		}
		return nil, ""
	}
	idx := arg.Index
	// A method call binds the receiver to the first parameter, which the argument list
	// does not carry.
	if c.ReceiverID != "" {
		switch callee.Params[0].Name {
		case "self", "cls", "this":
			idx++
		}
	}
	for _, p := range callee.Params {
		if p.Index == idx {
			return callee, p.ValueID
		}
	}
	return nil, ""
}

// argumentOf reports whether a value is an argument of a call and whether that binding
// is unambiguous.
func argumentOf(c *ir.Call, valueID string) (found ir.Arg, ok bool, unique bool) {
	count := 0
	for _, a := range c.Args {
		if a.ValueID == valueID {
			found = a
		}
	}
	if found.ValueID == "" {
		return ir.Arg{}, false, false
	}
	for _, a := range c.Args {
		if (found.Name != "" && a.Name == found.Name) ||
			(found.Name == "" && a.Name == "" && a.Index == found.Index) {
			count++
		}
	}
	return found, true, count == 1
}

// urlPart keeps the scheme and host of an address and drops the rest, so that the
// evidence names the service without reproducing a path or a query.
func urlPart(s string) string {
	if i := strings.Index(s, "="); i >= 0 && !strings.Contains(s[:i], "://") {
		s = s[i+1:]
	}
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		rest := s[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			return s[:i+3] + rest[:j]
		}
	}
	return s
}
