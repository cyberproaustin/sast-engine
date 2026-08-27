// Sibling analysis: a check one path makes and the path beside it does not.
//
// Everything else in this package reads a single function's graph. This reads two, and it
// is the only judgement the engine makes by comparison rather than by inspection --
// which is also the only honest way to say a check is MISSING. Nothing in a program
// declares what ought to guard an operation, so an engine that names one is guessing. It
// does not have to guess when the program has already written the check down on a
// neighbouring path over the same value: then the expected shape is the program's own,
// and the finding can cite it.
//
// That is the reasoning ADR-010's convention analysis uses against a population of peers,
// narrowed here to a pair. The narrowing costs the population's statistical safety, so
// everything the pair form gives back is spent on being specific: the same value, out of
// the same request, in the same module, with the direction of the difference fixed.
package guard

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// profile is what one function does with the values it takes off the request.
type profile struct {
	fn *ir.Function
	// reads is every request path the function gets its hands on -- `req.params.projectId`
	// and the `req.params` it came out of alike.
	reads map[string]bool
	// checked maps a path to the call that asked a question about it, and inputs to
	// every path that call was given. A check is a question about the values it was
	// handed TOGETHER: `validateFeatureBelongsToProject({featureName, projectId})` asks
	// whether those two agree, and a path holding only one of them cannot ask it.
	checked map[string]*ir.Call
	inputs  map[string]map[string]bool
	// used maps a path to the first call that does something with it other than write it
	// down.
	used map[string]*ir.Call
	// carries is every value in the function said as a request path, kept so a finding
	// can point at the argument position the unchecked value travelled in.
	carries map[string]map[string]bool

	reader, mutator bool
	// guarded records that a route-scoped middleware already asks. A check applied before
	// the handler runs is a check, and the handler's own body is the wrong place to look
	// for it.
	guarded bool
}

// siblingDifferential reports a write path that skips a check its sibling read path makes
// on the same request value.
func siblingDifferential(ix *ir.Index, d *ir.IR, rule model.GuardRule) []taint.Finding {
	byModule := map[string][]*profile{}
	var order []string
	for _, fn := range d.Functions {
		p := profileOf(ix, fn, rule)
		if p == nil {
			continue
		}
		if _, seen := byModule[fn.Loc.File]; !seen {
			order = append(order, fn.Loc.File)
		}
		byModule[fn.Loc.File] = append(byModule[fn.Loc.File], p)
	}

	var out []taint.Finding
	for _, file := range order {
		group := byModule[file]
		for _, weak := range group {
			if !weak.mutator || weak.guarded {
				continue
			}
			for _, strong := range group {
				if !strong.reader || strong.fn.ID == weak.fn.ID {
					continue
				}
				if f, ok := differ(ix, weak, strong, rule); ok {
					out = append(out, f)
					break
				}
			}
		}
	}
	return out
}

// differ finds the one path the strong handler asks about and the weak one does not, and
// returns the finding that names both.
func differ(ix *ir.Index, weak, strong *profile, rule model.GuardRule) (taint.Finding, bool) {
	paths := make([]string, 0, len(strong.checked))
	for p := range strong.checked {
		paths = append(paths, p)
	}
	// Deepest first, so the evidence names `req.params.featureName` rather than the
	// `req.params` it was read out of. Both are true and one of them says something.
	sort.Slice(paths, func(i, j int) bool {
		a, b := strings.Count(paths[i], "."), strings.Count(paths[j], ".")
		if a != b {
			return a > b
		}
		return paths[i] < paths[j]
	})

	for _, p := range paths {
		if weak.checked[p] != nil || !weak.reads[p] {
			continue
		}
		use := weak.used[p]
		if use == nil {
			continue
		}
		// Every value the check consumed has to be in the weak handler's hands. A check
		// it lacks an argument for is a different question about a different resource,
		// and the measured false positive was exactly that: a tag update sharing only
		// `projectId` with a check about a strategy it never sees.
		if !holdsAll(weak.reads, strong.inputs[p]) {
			continue
		}
		return siblingFinding(ix, weak, strong, p, use, strong.checked[p], rule), true
	}
	return taint.Finding{}, false
}

func holdsAll(reads map[string]bool, want map[string]bool) bool {
	for p := range want {
		if !reads[p] {
			return false
		}
	}
	return true
}

// profileOf reads one function, or reports that there is nothing here to compare: a
// function that takes no request holds no value a caller chose.
func profileOf(ix *ir.Index, fn *ir.Function, rule model.GuardRule) *profile {
	if ix.InTestModule(fn.Loc) {
		return nil
	}
	carries := requestPaths(fn, rule)
	if len(carries) == 0 {
		return nil
	}
	p := &profile{
		fn:      fn,
		reads:   map[string]bool{},
		checked: map[string]*ir.Call{},
		inputs:  map[string]map[string]bool{},
		used:    map[string]*ir.Call{},
		carries: carries,
		reader:  hasPrefix(fn.Name, rule.Reads),
		mutator: hasPrefix(fn.Name, rule.Mutates),
	}
	// A name that says both -- there is no such prefix pair -- and a name that says
	// neither are both unusable: the rule's whole safety is that the DIRECTION of the
	// difference is known.
	if p.reader == p.mutator {
		return nil
	}
	for _, s := range carries {
		for path := range s {
			p.reads[path] = true
		}
	}
	if ep, ok := ix.EntryByFunc[fn.ID]; ok {
		for _, mw := range ep.Middleware {
			name := mw.Name
			if name == "" {
				name = lastSegment(mw.Symbol)
			}
			if isCheck(name, rule) {
				p.guarded = true
			}
		}
	}

	for _, c := range fn.Calls {
		name := lastSegment(c.Callee.Symbol)
		if name == "" {
			name = c.Method
		}
		if name == "" {
			name = lastSegment(c.Callee.Name)
		}
		given := map[string]bool{}
		for _, a := range c.Args {
			for path := range carries[a.ValueID] {
				given[path] = true
			}
		}
		if len(given) == 0 {
			continue
		}
		switch {
		case isCheck(name, rule):
			for path := range given {
				if p.checked[path] == nil {
					p.checked[path] = c
					p.inputs[path] = given
				}
			}
		case hasPrefix(name, rule.Records) || matchesName(name, "", rule.Records):
			// Writing a value down is not operating on it.
		default:
			for path := range given {
				if p.used[path] == nil {
					p.used[path] = c
				}
			}
		}
	}
	return p
}

// requestPaths is what each value in a function is, said as a path out of the request:
// `req.params.projectId` for the property chain that produced it, and the same for
// anything the value was copied into.
//
// Written as paths rather than as value identities because the comparison is between two
// FUNCTIONS, which share no values at all. `req.params.featureName` is the only thing two
// handlers can be said to have in common, and it is exactly what a caller controls.
func requestPaths(fn *ir.Function, rule model.GuardRule) map[string]map[string]bool {
	vals := make(map[string]*ir.Value, len(fn.Values))
	for _, v := range fn.Values {
		vals[v.ID] = v
	}
	roots := map[string]string{}
	for _, prm := range fn.Params {
		if matchesName(prm.Name, "", rule.Containers) {
			roots[prm.ValueID] = strings.ToLower(prm.Name)
		}
	}
	if len(roots) == 0 {
		return nil
	}

	memo := map[string]string{}
	var resolve func(id string, depth int) string
	resolve = func(id string, depth int) string {
		if root, ok := roots[id]; ok {
			return root
		}
		if depth > 8 {
			return ""
		}
		if got, ok := memo[id]; ok {
			return got
		}
		memo[id] = ""
		v := vals[id]
		if v == nil || v.Kind != ir.ValueProperty || v.Base == "" || v.Path == "" {
			return ""
		}
		up := resolve(v.Base, depth+1)
		if up == "" {
			return ""
		}
		memo[id] = up + "." + leafPath(v.Path)
		return memo[id]
	}

	carries := map[string]map[string]bool{}
	for _, v := range fn.Values {
		if p := resolve(v.ID, 0); p != "" {
			carries[v.ID] = map[string]bool{p: true}
		}
	}
	// A destructured field is copied into a local before anything uses it, and the copy
	// is what the calls are given. Following the flows is what makes the two halves of
	// `const { projectId } = req.params; service.update(projectId)` one fact.
	for round := 0; round < 4; round++ {
		changed := false
		for _, f := range fn.Flows {
			src := carries[f.From]
			if len(src) == 0 {
				continue
			}
			dst := carries[f.To]
			if dst == nil {
				dst = map[string]bool{}
				carries[f.To] = dst
			}
			for p := range src {
				if !dst[p] {
					dst[p] = true
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	return carries
}

// isCheck reports whether a name ASKS something rather than fetching it.
//
// The prefix test is the half that matters. `hasPermission` judges and
// `getPermissionsForUser` fetches, and both contain the same word -- so a rule reading
// only the word would call a lookup a check and then report every path that did not
// perform one.
func isCheck(name string, rule model.GuardRule) bool {
	n := letters(name)
	if n == "" || hasPrefix(name, rule.Retrieves) {
		return false
	}
	for _, stem := range rule.Checks {
		if strings.Contains(n, stem) {
			return true
		}
	}
	return false
}

func hasPrefix(name string, prefixes []string) bool {
	n := letters(name)
	for _, p := range prefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// letters reduces a name to its letters so that `validate_username`, `validateUsername`
// and `ValidateUsername` are one name. Case and separators are an ecosystem's habit, not
// a fact about what the call does.
func letters(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func leafPath(p string) string {
	if i := strings.LastIndexByte(p, '.'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// argCarrying is the position the unchecked value was passed in, so the finding points at
// the argument rather than at the call generally.
func argCarrying(use *ir.Call, weak *profile, path string) int {
	for _, a := range use.Args {
		if a.Name == "" && weak.carries[a.ValueID][path] {
			return a.Index
		}
	}
	return -1
}

func siblingFinding(ix *ir.Index, weak, strong *profile, path string, use, check *ir.Call,
	rule model.GuardRule) taint.Finding {
	asks := callName(ix, check)
	return taint.Finding{
		Analysis:     rule.ID,
		DataClass:    "control-flow",
		ChannelID:    rule.ID,
		Class:        rule.Finding,
		CWE:          rule.CWE,
		Message:      rule.Reason,
		SinkLoc:      use.Loc,
		SinkSymbol:   callName(ix, use),
		SinkFunction: weak.fn.Name,
		SinkRational: rule.Rationale,
		SourceLabel:  path,
		SourceLoc:    check.Loc,
		InTestModule: ix.InTestModule(use.Loc),
		Path: []taint.Hop{
			{Loc: strong.fn.Loc, Description: fmt.Sprintf("%s() is the sibling path on this resource, and it reads the same %s", strong.fn.Name, path), Resolution: ir.Resolved},
			{Loc: check.Loc, Description: fmt.Sprintf("%s() asks about it there, which is the check this resource has", asks), Resolution: ir.Resolved},
			{Loc: use.Loc, Description: fmt.Sprintf("%s() acts on the same %s here without it", callName(ix, use), path), Resolution: ir.Resolved},
		},
		SinkArgIndex:  argCarrying(use, weak, path),
		Confidence:    taint.High,
		EntryAnchored: true,
		EntryPoint:    entryAbove(ix, parents(ix), weak.fn),
	}
}
