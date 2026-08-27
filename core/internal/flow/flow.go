// Package flow joins a program's two halves where a frontend cannot.
//
// A server-rendered application decides its escaping in a file the language's own
// compiler has never heard of, and it supplies the values from somewhere else entirely.
// Until this package existed the two were joined at the render call, which meant an
// unescaped interpolation was reported only where the call named the view AND built its
// context in the same place. Real applications do not do that: a base handler adds the
// application-wide namespace, a helper forwards the view name it was handed, a page
// EXTENDS the file that actually writes the markup, and an element template is INCLUDED
// from inside a loop over the list the handler passed.
//
// So the frontend states two facts — these are the views, these are the renders — and
// the join happens here, program-wide. A view's free variables are sinks in their own
// right, and a value reaches one if it reaches any context handed to a render of that
// view anywhere.
//
// The join produces IR, not findings. What it writes back into the program is the same
// shape a colocated render used to be lowered as: a call, at the TEMPLATE's location,
// carrying the value the context bound to that interpolation's name. Every rule that
// already knew what `<template>.unescaped` means keeps working, and the analyses below
// it never learn that a template exists.
package flow

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

// Sink symbols. The core half of the contract the frontends already wrote against: an
// interpolation the engine escapes, and one it does not.
const (
	SymbolEscaped   = "<template>.escaped"
	SymbolUnescaped = "<template>.unescaped"
)

// Report is what the join did, for the surface summary.
type Report struct {
	Views   int
	Renders int
	// Resolved is how many renders were tied to a view, including those whose name was
	// only knowable at a call site.
	Resolved int
	// Sinks is how many interpolations gained a value.
	Sinks int
}

// JoinViews ties every render to the views it reaches and writes the resulting
// interpolation sinks into the program.
//
// Idempotent: a document already joined is left alone, because a scan may be run twice
// over one IR and a second pass would double every finding.
func JoinViews(d *ir.IR) Report {
	rep := Report{Views: len(d.Views), Renders: len(d.Renders)}
	if len(d.Views) == 0 || len(d.Renders) == 0 || d.ViewsJoined {
		return rep
	}
	d.ViewsJoined = true

	views := make(map[string]*ir.View, len(d.Views))
	ids := make([]string, 0, len(d.Views))
	for i := range d.Views {
		views[d.Views[i].ID] = &d.Views[i]
		ids = append(ids, d.Views[i].ID)
	}
	sort.Strings(ids)

	ix := ir.NewIndex(d)
	byID := make(map[string]*ir.Function, len(d.Functions))
	for _, fn := range d.Functions {
		byID[fn.ID] = fn
	}

	w := &writer{views: views, byID: byID, seen: make(map[string]bool)}
	for _, r := range resolveRenders(d, ix, ids) {
		rep.Resolved++
		rep.Sinks += w.render(r)
	}
	return rep
}

// --- resolving a render to a view ----------------------------------------

// resolved is a render whose view is known and whose bindings are complete.
type resolved struct {
	View     string
	Name     string
	Function string
	Loc      ir.Loc
	Block    string
	Bind     map[string]string
}

// resolveRenders answers, for every render in the program, which view it renders and
// what names it bound — including the renders whose view is named by whoever called the
// function they sit in.
func resolveRenders(d *ir.IR, ix *ir.Index, ids []string) []resolved {
	var out []resolved
	for i := range d.Renders {
		r := d.Renders[i]
		switch {
		case r.View != "":
			out = append(out, resolved{
				View: r.View, Name: r.Name, Function: r.FunctionID,
				Loc: r.Loc, Block: r.Block, Bind: bindingsOf(r.Bindings, nil),
			})
		case r.FromParam != "":
			out = append(out, atCallSites(r, ix, ids)...)
		}
	}
	return out
}

// atCallSites resolves a render whose view name is a parameter of the function it sits
// in, by reading the name each caller wrote.
//
// The sink stays at the CALLER, which is where the value came from and what an entry
// point reaches. A base handler's `render_template` is one function shared by every page
// in the application, and attributing every page's context to it would put one pile of
// unrelated values in one place.
func atCallSites(r ir.Render, ix *ir.Index, ids []string) []resolved {
	fn := ix.FuncByID[r.FunctionID]
	if fn == nil {
		return nil
	}
	index := -1
	for _, p := range fn.Params {
		if p.Name == r.FromParam {
			index = p.Index
			break
		}
	}
	if index < 0 {
		return nil
	}
	var out []resolved
	for _, c := range ix.CallSitesOf[r.FunctionID] {
		name, ok := c.ArgLiterals[index]
		if !ok || name == ir.UnknownLiteral || name == "" {
			continue
		}
		view := resolveName(ids, name)
		if view == "" {
			continue
		}
		caller := ix.OwnerOfCall[c.ID]
		if caller == nil {
			continue
		}
		bind := bindingsOf(r.Bindings, nil)
		if r.ForwardsKeywords {
			// The caller's own keyword arguments are the view's names. Only the ones
			// the frontend could read: a call that spreads a mapping it did not
			// enumerate binds nothing here, and binding a value to a name nobody wrote
			// would attach the finding to the wrong interpolation.
			for k, v := range keywordArgs(c, ix) {
				bind[k] = v
			}
		}
		out = append(out, resolved{
			View: view, Name: name, Function: caller.ID,
			Loc: c.Loc, Block: c.Block, Bind: bind,
		})
	}
	return out
}

// keywordArgs is what a call bound by NAME, for the frontends that record it.
//
// A keyword argument appears in `argLiterals` under a negative index spelled
// `name=value`, and its VALUE — the thing dataflow tracks — is an ordinary entry in
// `args` at the position keyword arguments start. Pairing the two by order is what the
// caller's own lowering guarantees.
func keywordArgs(c *ir.Call, ix *ir.Index) map[string]string {
	out := map[string]string{}
	if !c.OptionsEnumerated(-1) {
		return out
	}
	var names []string
	keys := make([]int, 0, len(c.ArgLiterals))
	for k := range c.ArgLiterals {
		if k < 0 && k > -1000 {
			keys = append(keys, k)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(keys)))
	for _, k := range keys {
		name, _, ok := strings.Cut(c.ArgLiterals[k], "=")
		if !ok {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return out
	}
	// Keyword arguments are lowered at one position, in the order they were written.
	var values []string
	for _, a := range c.Args {
		if a.ValueID != "" {
			values = append(values, a.ValueID)
		}
	}
	if len(values) < len(names) {
		return out
	}
	tail := values[len(values)-len(names):]
	for i, name := range names {
		if ix.ValueByID[tail[i]] != nil {
			out[name] = tail[i]
		}
	}
	return out
}

func bindingsOf(bs []ir.Binding, into map[string]string) map[string]string {
	if into == nil {
		into = make(map[string]string, len(bs))
	}
	for _, b := range bs {
		into[b.Name] = b.ValueID
	}
	return into
}

// resolveName is which view a name reaches.
//
// A loader resolves a view name against a search path that is configuration rather than
// source, so matching on a path SUFFIX covers it without modelling that configuration.
// An ambiguous name — two views whose paths both end this way — resolves to nothing:
// picking one would attach a finding to a file that may not be the one rendered, and a
// finding pointing at the wrong file is worse than no finding.
func resolveName(ids []string, name string) string {
	if strings.Contains(name, "..") {
		return ""
	}
	want := strings.TrimLeft(name, "./")
	if want == "" {
		return ""
	}
	var hits []string
	for _, id := range ids {
		if id == want || strings.HasSuffix(id, "/"+want) {
			hits = append(hits, id)
		}
	}
	if len(hits) == 1 {
		return hits[0]
	}
	var inViews []string
	for _, id := range hits {
		if strings.HasPrefix(id, "templates/") || strings.Contains(id, "/templates/") {
			inViews = append(inViews, id)
		}
	}
	if len(inViews) == 1 {
		return inViews[0]
	}
	return ""
}

// --- writing the sinks ----------------------------------------------------

type writer struct {
	views map[string]*ir.View
	byID  map[string]*ir.Function
	seen  map[string]bool
	n     int
}

// reachedView is one view a render reaches, and what the names inside it stand for in
// the context the render supplied.
type reachedView struct {
	id     string
	rebind map[string]string
}

// reach walks a view's own graph: the parents it fills in and the files it draws in,
// each of which is rendered with the SAME context. A rebinding accumulates through
// includes, because a view included from inside a loop reads a name that only exists
// there.
func (w *writer) reach(id string) []reachedView {
	out := []reachedView{}
	seen := map[string]bool{}
	var walk func(id string, rebind map[string]string)
	walk = func(id string, rebind map[string]string) {
		key := id + "\x00" + fingerprint(rebind)
		if seen[key] {
			return
		}
		seen[key] = true
		v := w.views[id]
		if v == nil {
			return
		}
		out = append(out, reachedView{id: id, rebind: rebind})
		for _, parent := range v.Extends {
			walk(parent, rebind)
		}
		for _, inc := range v.Includes {
			walk(inc.View, compose(inc.Rebind, rebind))
		}
	}
	walk(id, nil)
	return out
}

// compose applies an outer rebinding to an inner one, so a name three includes deep
// still names something the render call passed.
func compose(inner, outer map[string]string) map[string]string {
	if len(inner) == 0 {
		return outer
	}
	out := make(map[string]string, len(inner)+len(outer))
	for k, v := range inner {
		out[k] = rebindPath(v, outer)
	}
	for k, v := range outer {
		if _, ok := out[k]; !ok {
			out[k] = v
		}
	}
	return out
}

// rebindPath renames a path's ROOT. Only the root can be rebound: everything below it is
// a field of whatever the root turned out to be.
func rebindPath(path string, rebind map[string]string) string {
	if len(rebind) == 0 {
		return path
	}
	root, rest, _ := strings.Cut(path, ".")
	to, ok := rebind[root]
	if !ok {
		return path
	}
	if rest == "" {
		return to
	}
	return to + "." + rest
}

func fingerprint(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte(';')
	}
	return b.String()
}

// render writes one render's sinks and answers how many it wrote.
func (w *writer) render(r resolved) int {
	fn := w.byID[r.Function]
	if fn == nil {
		return 0
	}
	written := 0
	for _, reached := range w.reach(r.View) {
		v := w.views[reached.id]
		if v == nil {
			continue
		}
		for _, read := range v.Reads {
			path := rebindPath(read.Path, reached.rebind)
			root, rest, _ := strings.Cut(path, ".")
			src, ok := r.Bind[root]
			if !ok || src == "" {
				continue
			}
			// One sink per interpolation per bound value. Two handlers rendering the
			// same page bind the same name to two different values and each is a real
			// path; the same handler reaching one interpolation twice is not.
			key := fn.ID + "\x00" + read.Loc.String() + "\x00" + src
			if w.seen[key] {
				continue
			}
			w.seen[key] = true
			w.write(fn, read, src, rest, r.Block)
			written++
		}
	}
	return written
}

func (w *writer) write(fn *ir.Function, read ir.ViewRead, src, rest, block string) {
	at := read.Loc
	value := src
	if rest != "" {
		// The path BELOW the root is a read out of the value the context supplied, and
		// every rule that asks what a field is called reads it this way.
		id := w.id(fn, "v")
		fn.Values = append(fn.Values, &ir.Value{
			ID: id, Kind: ir.ValueProperty, Loc: at, Base: src, Path: rest, Name: rest,
		})
		fn.Flows = append(fn.Flows, ir.Flow{From: src, To: id, Kind: "property", Loc: at, Block: block})
		value = id
	}
	symbol := SymbolUnescaped
	if read.Escaped {
		symbol = SymbolEscaped
	}
	result := w.id(fn, "v")
	fn.Values = append(fn.Values, &ir.Value{ID: result, Kind: ir.ValueCallResult, Loc: at, Name: symbol})
	call := &ir.Call{
		ID:       w.id(fn, "c"),
		Loc:      at,
		Callee:   ir.Callee{Kind: "external", Symbol: symbol, Resolution: ir.Resolved},
		Args:     []ir.Arg{{Index: 0, ValueID: value}},
		ArgCount: 1,
		ResultID: result,
		Block:    block,
	}
	fn.Calls = append(fn.Calls, call)
}

func (w *writer) id(fn *ir.Function, kind string) string {
	w.n++
	return fmt.Sprintf("%s$tpl%s%d", fn.ID, kind, w.n)
}
