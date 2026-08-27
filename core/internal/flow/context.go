package flow

import (
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

// A template's context is a mapping, and the render call is routinely not where it was
// filled in.
//
// `render_template("page.html", query=q)` names every variable at the call, and that is
// the shape a frontend could join by itself. It is also the shape real applications stop
// having as soon as they have more than one page: Django offers no keyword form at all
// and hands one dict over whole, a Flask application grows a `render()` helper that adds
// the application-wide values to whatever keywords it was passed, and a framework's base
// handler mutates a namespace that a subclass never sees.
//
// So the frontend states which VALUE was handed over and this answers which names it
// carries, from the whole program rather than from the call. Every answer here rests on a
// key somebody wrote as a literal: a mapping literal's entries, an assignment into a
// subscript or an attribute, a `dict(name=value)` call, an `update` with another mapping,
// and the mapping a called function returns. A computed key names nothing a view can
// read, and a name nobody wrote binds nothing — attaching a finding to the wrong
// interpolation is worse than attaching it to none.

// mappingHops is how far the search follows construction: the value handed to the render,
// the local it was assigned from, and the function that returned it.
//
// Three is the depth of the shapes that exist: `ctx = {...}; render(..., ctx)` is two, and
// `render(..., **build_context())` is three. A fourth buys reach into code that no longer
// resembles a context and costs one more way to bind a name wrongly.
const mappingHops = 3

// context is what a render's mappings supply, by name.
//
// Later definitions win, in the order a reader would resolve them: what the mapping was
// CONSTRUCTED as, then what was written INTO it. `template_ns.update(namespace)` followed
// by `template_ns["xsrf_token"] = ...` is one mapping with a dozen names and one of them
// replaced, and reading it in the other order would answer with the value that was
// overwritten.
func (w *writer) context(r ir.Render) map[string]string {
	out := map[string]string{}
	for _, id := range r.ContextValues {
		for name, value := range w.mapping(id, mappingHops) {
			out[name] = value
		}
	}
	return out
}

// mapping answers what names one mapping value carries.
func (w *writer) mapping(id string, hops int) map[string]string {
	out := map[string]string{}
	if id == "" || hops <= 0 || w.open[id] {
		return out
	}
	// A mapping that reaches itself — `ctx = ctx or {}`, a merge of two branches — is
	// walked once. Without this a cycle in the value graph is not a wrong answer but a
	// hang, and a scanner reads inputs an attacker may have written.
	w.open[id] = true
	defer delete(w.open, id)

	fn := w.ix.OwnerOfValue[id]
	if fn == nil {
		return out
	}
	if v := w.ix.ValueByID[id]; v != nil {
		for _, e := range v.Entries {
			if e.Key != "" && e.ValueID != "" {
				out[e.Key] = e.ValueID
			}
		}
	}
	// What flowed INTO this value. `ctx = {"query": q}` is a local with an edge from the
	// literal, and the literal is where the keys are; the local is what the call names.
	for _, f := range fn.Flows {
		if f.To == id && f.From != id {
			merge(out, w.mapping(f.From, hops-1))
		}
	}
	for _, c := range fn.Calls {
		if c.ResultID == id {
			merge(out, w.constructed(c, hops))
		}
		// `ns.update(other)` is the base-class hook, spelled the same way in every
		// framework that has one: the caller's mapping is filled in from a mapping it
		// never named.
		if c.ReceiverID == id && c.Method == "update" {
			for _, a := range c.Args {
				if a.Name == "" && a.ValueID != "" {
					merge(out, w.mapping(a.ValueID, hops-1))
				}
			}
		}
	}
	for _, wr := range fn.Writes {
		if wr.Base == id && wr.Path != "" && wr.From != "" {
			out[wr.Path] = wr.From
		}
	}
	return out
}

// constructed is what the call that PRODUCED a mapping put in it: the keywords of a
// `dict(...)`, or whatever the function it called returns.
func (w *writer) constructed(c *ir.Call, hops int) map[string]string {
	out := map[string]string{}
	if name := calleeName(c); name == "dict" {
		for _, a := range c.Args {
			if a.Name != "" && a.ValueID != "" {
				out[a.Name] = a.ValueID
			}
		}
		return out
	}
	// A helper that builds the context and hands it back is the one shape that puts the
	// keys in a different function from the call, and it is the common one: a base
	// handler's namespace, a `build_context()` beside the view.
	for _, id := range calleeFunctions(c) {
		callee := w.ix.FuncByID[id]
		if callee == nil {
			continue
		}
		for _, ret := range callee.Returns {
			merge(out, w.mapping(ret, hops-1))
		}
	}
	return out
}

// calleeName is what a call was written as, on its last segment. `dict(a=1)` and a
// module-qualified spelling of it are the same constructor.
func calleeName(c *ir.Call) string {
	name := c.Callee.Name
	if name == "" {
		name = c.Callee.Symbol
	}
	if c.Method != "" {
		name = c.Method
	}
	return lastSegment(name)
}

func lastSegment(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return s[i+1:]
		}
	}
	return s
}

// calleeFunctions are the functions a call may enter. An indirect call the frontend could
// enumerate contributes every member: each is a mapping this render may have been handed,
// and one of them is the one it was.
func calleeFunctions(c *ir.Call) []string {
	if c.Callee.FunctionID != "" {
		return []string{c.Callee.FunctionID}
	}
	return c.Callee.PossibleFunctionIDs
}

func merge(into, from map[string]string) {
	for k, v := range from {
		into[k] = v
	}
}
