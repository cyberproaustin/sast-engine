package surface

import (
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
)

func TestZZReachDiag(t *testing.T) {
	path := os.Getenv("DIAG_IR")
	if path == "" {
		t.Skip("set DIAG_IR")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := ir.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	m := model.Builtin()
	s := Build(d, m, nil)
	ix := ir.NewIndex(d)

	kinds := map[string]bool{}
	globals := map[string]bool{}
	paths := map[string]bool{}
	for _, c := range m.Classifications {
		if c.Class != m.UntrustedClass() {
			continue
		}
		for _, r := range c.Rules {
			switch r.Match {
			case model.MatchValueKind:
				kinds[r.ValueKind] = true
			case model.MatchGlobalProperty:
				globals[r.Symbol] = true
			default:
				for _, p := range r.Paths {
					paths[p] = true
				}
			}
		}
	}
	roots := []string{}
	for _, e := range s.Entries {
		if e.EntryPoint.FunctionID != "" {
			roots = append(roots, e.EntryPoint.FunctionID)
		}
	}
	reachable := ix.ReachableFrom(roots)

	// every name written at a call site that did NOT resolve to a local function,
	// and whether the calling function is itself reachable.
	unresolvedName := map[string]bool{}
	unresolvedNameFromReached := map[string]bool{}
	for _, fn := range d.Functions {
		for _, c := range fn.Calls {
			if c.Callee.Kind == "local" && c.Callee.FunctionID != "" {
				continue
			}
			for _, n := range []string{c.Method, c.Callee.Name, c.Callee.Symbol} {
				if n == "" {
					continue
				}
				unresolvedName[n] = true
				if reachable[fn.ID] {
					unresolvedNameFromReached[n] = true
				}
			}
		}
	}

	readsOf := func(fn *ir.Function) (bool, string, string) {
		params := map[string]string{}
		for _, p := range fn.Params {
			params[p.ValueID] = p.Name
		}
		for _, v := range fn.Values {
			if kinds[string(v.Kind)] {
				return true, "", string(v.Kind)
			}
			base := ix.ValueByID[v.Base]
			if base != nil && base.Kind == "global" && globals[base.Name] {
				return true, "", base.Name
			}
			if v.Kind == ir.ValueProperty {
				if name, ok := params[v.Base]; ok && paths[firstSegment(v.Path)] {
					return true, name, firstSegment(v.Path)
				}
			}
		}
		return false, "", ""
	}

	type rec struct {
		fn     *ir.Function
		param  string
		path   string
		cause  string
		detail string
	}
	var recs []rec
	appTotal := 0
	for _, fn := range d.Functions {
		ok, p, pa := readsOf(fn)
		if !ok || !ix.InApplicationSurface(fn.Loc) {
			continue
		}
		appTotal++
		if reachable[fn.ID] {
			continue
		}
		r := rec{fn: fn, param: p, path: pa}
		switch {
		case len(ix.CallSitesOf[fn.ID]) > 0:
			r.cause = "C-caller-unreached"
		case unresolvedNameFromReached[fn.Name]:
			r.cause = "A-unresolved-call-from-reached-code"
		case unresolvedName[fn.Name]:
			r.cause = "B-unresolved-call-elsewhere"
		default:
			r.cause = "D-never-called-by-name (framework-invoked or dead)"
		}
		recs = append(recs, r)
	}
	fmt.Printf("input=%d unreached=%d\n", appTotal, len(recs))
	byCause := map[string]int{}
	for _, r := range recs {
		byCause[r.cause]++
	}
	type kv struct {
		k string
		v int
	}
	var xs []kv
	for k, v := range byCause {
		xs = append(xs, kv{k, v})
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].v > xs[j].v })
	for _, x := range xs {
		fmt.Printf("  %4d  %s\n", x.v, x.k)
	}
	shown := map[string]int{}
	for _, r := range recs {
		if shown[r.cause] >= 10 {
			continue
		}
		shown[r.cause]++
		fmt.Printf("    [%s] %s (%s.%s) %s:%d\n", r.cause[:1], r.fn.Name, r.param, r.path, r.fn.Loc.File, r.fn.Loc.Line)
	}
}
