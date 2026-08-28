// Package callshape finds weaknesses visible in a call's own arguments.
//
// The engine's third analysis kind, and the one a large part of the CWE catalog actually
// needs. A flow analysis asks whether untrusted data reaches somewhere dangerous; a
// convention analysis asks whether an entry point has what its peers have. Neither can
// express `createHash("md5")`, which is weak wherever it is written, with nothing reaching
// it and no caller controlling anything.
//
// Deliberately narrow. It matches a LITERAL argument only. A value computed at runtime is
// not matched and not guessed at, which keeps this kind at the precision that makes it
// worth having: a string "md5" handed to a hash constructor is md5, and there is nothing
// to be wrong about.
package callshape

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// Analyze reports every call whose written arguments make it a defect.
func Analyze(d *ir.IR, m model.Model, classified map[string]taint.Classified) []taint.Finding {
	if len(m.CallShapes) == 0 {
		return nil
	}
	ix := ir.NewIndex(d)
	flowsInto := make(map[string][]ir.Flow)
	callByResult := make(map[string]*ir.Call)
	for _, fn := range d.Functions {
		for _, f := range fn.Flows {
			flowsInto[f.To] = append(flowsInto[f.To], f)
		}
		for _, c := range fn.Calls {
			if c.ResultID != "" {
				callByResult[c.ResultID] = c
			}
		}
	}

	// Skipping calls with no written arguments is worth a great deal on a large program,
	// and it is only sound while every shape needs an argument to look at. A shape that
	// matches the call ITSELF has none -- `tempfile.mktemp()` takes nothing -- so the
	// shortcut has to know whether any such shape exists before it can take it.
	callIsEnough := false
	for _, shape := range m.CallShapes {
		// A shape that reads a literal needs one; a shape that asks where an argument
		// CAME FROM does not, and a call whose arguments are all variables is exactly the
		// case it exists for.
		if shape.Always || shape.ArgFromModuleScope != nil || shape.MissingArg != nil || shape.InputClass != "" {
			callIsEnough = true
			break
		}
	}

	// Judged once over the whole program, because that is the scope of the question:
	// "does this application anywhere disable the header" has one answer, not one per
	// call site.
	var out []taint.Finding
	for _, fn := range d.Functions {
		for _, c := range fn.Calls {
			if len(c.ArgLiterals) == 0 && !callIsEnough {
				continue
			}
			for _, shape := range m.CallShapes {
				if shape.ExcludeTestModule && ix.InTestModule(c.Loc) {
					continue
				}
				if !targets(shape, c) {
					continue
				}
				if len(shape.ReceiverFromCall) > 0 && !receiverMadeBy(d, c, shape.ReceiverFromCall) {
					continue
				}
				if shape.ExternalDestinationArg != nil &&
					destinationStaysOnOrigin(ix, flowsInto, callByResult, c, *shape.ExternalDestinationArg) {
					continue
				}
				inputID, inputOrigin, hasInput := classifiedOperand(c, shape, classified)
				if shape.InputClass != "" && !hasInput {
					continue
				}
				// A claim about the attack surface has to be held to it: a schema in a
				// script or in a module nothing routes to has no caller (ADR-009). A route
				// registered in a TEST module is a fixture rather than a surface, and the
				// frontend cannot tell one `app.post` from another -- so the rule says it
				// here rather than leaving the finding to be filtered downstream, where it
				// would still be counted.
				if shape.EntryReachable {
					if _, ok := taint.EntryOf(ix, fn); !ok {
						continue
					}
					if ix.InTestModule(c.Loc) {
						continue
					}
				}
				if shape.ConfigurationEnabled && shape.DependsOnUse == "" {
					if condition := enclosingConfigurationCondition(ix, fn, c); condition != "" {
						shape.DependsOnUse = fmt.Sprintf("whether this behavior reaches deployment depends on the enclosing configuration condition %s; environment and configuration flags can be unset or mis-set, so the source does not guarantee this branch is unreachable", condition)
					}
				}
				if shape.PatternArg != nil {
					pattern, ok := c.ArgLiterals[*shape.PatternArg]
					if !ok || !model.CatastrophicPattern(pattern) {
						continue
					}
					out = append(out, finding(ix, fn, c, shape, pattern))
					continue
				}
				if shape.ArgFromModuleScope != nil {
					if !boundAtModuleScope(ix, c, *shape.ArgFromModuleScope) {
						continue
					}
					out = append(out, finding(ix, fn, c, shape, callName(c)))
					continue
				}
				lit, ok := match(c, shape)
				if !ok {
					continue
				}
				f := finding(ix, fn, c, shape, lit)
				if shape.InputClass != "" {
					f = findingFromInput(ix, c, shape, inputID, inputOrigin, f)
				}
				out = append(out, f)
			}
		}
	}
	return out
}

func destinationStaysOnOrigin(ix *ir.Index, flowsInto map[string][]ir.Flow,
	callByResult map[string]*ir.Call, c *ir.Call, index int,
) bool {
	for _, arg := range c.Args {
		if arg.At(index) {
			return valueStaysOnOrigin(ix, flowsInto, callByResult, arg.ValueID, map[string]bool{}, 0)
		}
	}
	return false
}

// valueStaysOnOrigin proves one of the two source-visible local URL shapes: a root-
// relative route, or an object URL this page itself created. It follows plain bindings
// and a resolved local helper's return because moving route construction into a helper
// does not change what the browser parses. Unknown and mixed returns stay reportable.
func valueStaysOnOrigin(ix *ir.Index, flowsInto map[string][]ir.Flow,
	callByResult map[string]*ir.Call, id string, seen map[string]bool, depth int,
) bool {
	if id == "" || depth >= 12 || seen[id] {
		return false
	}
	seen[id] = true
	defer delete(seen, id)

	if v := ix.ValueByID[id]; v != nil && v.Kind == ir.ValueLiteral {
		return model.RootRelativeURLPrefix(v.Literal)
	}
	if c := callByResult[id]; c != nil {
		switch strings.ToLower(c.Callee.Symbol) {
		case "url.createobjecturl", "window.url.createobjecturl":
			return true
		}
		if callee := ix.FuncByID[c.Callee.FunctionID]; callee != nil && len(callee.Returns) > 0 {
			for _, returned := range callee.Returns {
				if !valueStaysOnOrigin(ix, flowsInto, callByResult, returned, seen, depth+1) {
					return false
				}
			}
			return true
		}
	}

	// Template and binary contributors are emitted in source order. The first is the
	// prefix the URL parser sees; later path segments cannot turn `/Resource/` into an
	// authority. `//` and `/\` fail RootRelativeURLPrefix before that conclusion is made.
	if into := flowsInto[id]; len(into) > 0 {
		switch into[0].Kind {
		case "assign", "template", "binary":
			return valueStaysOnOrigin(ix, flowsInto, callByResult, into[0].From, seen, depth+1)
		}
	}
	return false
}

func classifiedOperand(c *ir.Call, shape model.CallShape, classified map[string]taint.Classified) (string, taint.Origin, bool) {
	if shape.InputClass == "" {
		return "", taint.Origin{}, false
	}
	class := classified[shape.InputClass]
	id := ""
	if shape.InputReceiver {
		id = c.ReceiverID
	} else if shape.InputArg != nil {
		for _, arg := range c.Args {
			if arg.At(*shape.InputArg) {
				id = arg.ValueID
				break
			}
		}
	}
	if id == "" || !class.Values[id] {
		return "", taint.Origin{}, false
	}
	origin := class.Origin[id]
	if shape.RemoteInput && origin.Trust != "" && origin.Trust != ir.Remote {
		return "", taint.Origin{}, false
	}
	return id, origin, true
}

func findingFromInput(ix *ir.Index, c *ir.Call, shape model.CallShape, inputID string, origin taint.Origin, f taint.Finding) taint.Finding {
	f.DataClass = shape.InputClass
	f.SourceLabel = origin.Label
	f.EntryPoint = origin.EntryPoint
	f.EntryMethod = origin.Method
	f.EntryPath = origin.Path
	f.EntryAnchored = origin.Anchored
	f.EntryTrust = origin.Trust
	if value := ix.ValueByID[inputID]; value != nil {
		f.SourceLoc = value.Loc
		f.Path = append([]taint.Hop{{
			Loc:         value.Loc,
			Description: origin.Label + " supplies the receiver",
			Resolution:  ir.Resolved,
		}}, f.Path...)
	}
	// The source classification, rather than the missing argument text, distinguishes
	// this finding from a literal call shape in reports and baselines.
	f.Discriminator = shape.InputClass
	return f
}

func enclosingConfigurationCondition(ix *ir.Index, fn *ir.Function, sink *ir.Call) string {
	if sink.Block == "" {
		return ""
	}
	g := cfg.Build(fn)
	if g == nil {
		return ""
	}
	for _, comparison := range fn.Comparisons {
		if comparison.Block == "" || !g.ControlDependsOn(sink.Block, comparison.Block) {
			continue
		}
		left := configurationValue(ix, comparison.Left)
		right := configurationValue(ix, comparison.Right)
		if left == "" && right == "" {
			continue
		}
		if left == "" {
			left, right = right, literalValue(ix, comparison.Left)
		} else {
			right = literalValue(ix, comparison.Right)
		}
		if comparison.Op == "truthy" {
			return "`" + left + "` being truthy"
		}
		if right == "" {
			return fmt.Sprintf("`%s %s ...`", left, comparison.Op)
		}
		return fmt.Sprintf("`%s %s %s`", left, comparison.Op, strconv.Quote(right))
	}
	return ""
}

func configurationValue(ix *ir.Index, id string) string {
	v := ix.ValueByID[id]
	if v == nil || v.Kind == ir.ValueLiteral {
		return ""
	}
	name := v.Path
	if name == "" {
		name = v.Name
	}
	lower := strings.ToLower(name)
	configurationNamed := false
	for _, word := range []string{"env", "config", "setting", "debug", "development", "production"} {
		if strings.Contains(lower, word) {
			configurationNamed = true
			break
		}
	}
	if !configurationNamed {
		return ""
	}
	root := v
	for root.Base != "" {
		root = ix.ValueByID[root.Base]
		if root == nil {
			return ""
		}
	}
	// A request field named `debug` is still caller input. Deployment configuration is
	// rooted outside the handler, in a global/imported value rather than a parameter.
	rootName := strings.ToLower(root.Name)
	if root.Kind == ir.ValueParam || rootName == "request" || rootName == "req" || strings.HasSuffix(rootName, ".request") {
		return ""
	}
	return name
}

func literalValue(ix *ir.Index, id string) string {
	if v := ix.ValueByID[id]; v != nil && v.Kind == ir.ValueLiteral {
		return v.Literal
	}
	return ""
}

// keyIs compares an option key on its LAST segment, because an option that decides
// something is routinely written inside a named group -- `webPreferences.nodeIntegration`,
// `httpsAgent.rejectUnauthorized`, `cookie.maxAge` -- and the group it sits in is not what
// makes it a decision. The frontend keeps the parent so the nesting stays visible in the
// evidence.
func keyIs(key, want string) bool {
	key = strings.ToLower(key)
	if i := strings.LastIndex(key, "."); i >= 0 {
		key = key[i+1:]
	}
	return key == want
}

// receiverMadeBy reports whether the object a method was called on came out of one of
// these calls, following plain assignments back so that a handle stored in a variable
// still answers the question.
//
//	with tarfile.open(path) as tar:
//	    tar.extractall(dest)      // the receiver is `tar`, and `tar` is a tarfile
func receiverMadeBy(d *ir.IR, c *ir.Call, symbols []string) bool {
	byResult := map[string]*ir.Call{}
	assigned := map[string]string{}
	for _, fn := range d.Functions {
		for _, call := range fn.Calls {
			if call.ResultID != "" {
				byResult[call.ResultID] = call
			}
		}
		for _, f := range fn.Flows {
			if f.Kind == "assign" && f.From != "" && f.To != "" {
				assigned[f.To] = f.From
			}
		}
	}
	id := c.ReceiverID
	for hops := 0; hops < 8 && id != ""; hops++ {
		if made := byResult[id]; made != nil {
			name := made.Callee.Symbol
			for _, want := range symbols {
				if strings.EqualFold(name, want) || strings.EqualFold(lastDot(name), lastDot(want)) {
					return true
				}
			}
			return false
		}
		id = assigned[id]
	}
	return false
}

func lastDot(s string) string {
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// boundAtModuleScope reports whether an argument resolves to a value the module owns --
// computed once when the file loaded, and the same on every call afterwards.
//
// Only a DIRECT reference counts. Following it through assignments would start answering
// a question about the value's history rather than about where it lives, and the two stop
// agreeing as soon as a function copies it into a local.
func boundAtModuleScope(ix *ir.Index, c *ir.Call, index int) bool {
	for _, a := range c.Args {
		if !a.At(index) || a.ValueID == "" {
			continue
		}
		owner := ix.OwnerOfValue[a.ValueID]
		return owner != nil && owner.Name == "<module>"
	}
	return false
}

func targets(shape model.CallShape, c *ir.Call) bool {
	// The chain the receiver was built from, when the shape asks for one. A method name
	// on its own says too little: `regex` is a method on a validation schema and on
	// plenty of other things.
	if len(shape.SymbolContains) > 0 && !containsAny(c.Callee.Symbol, shape.SymbolContains) {
		return false
	}
	if shape.Symbol != "" {
		return c.Callee.Symbol == shape.Symbol
	}
	if shape.Method != "" {
		return c.Method == shape.Method
	}
	return shape.AnyCall
}

func containsAny(symbol string, wants []string) bool {
	for _, want := range wants {
		if strings.Contains(symbol, want) {
			return true
		}
	}
	return false
}

// match finds the literal this shape forbids, if the call carries one.
//
// A positional argument is read by index. A negative index means a keyword argument, and
// every one of them is checked rather than the first: Go map iteration is randomized, so
// reading whichever came out first made `requests.get(url, timeout=5, verify=False)`
// report or not report depending on the run. A scanner that answers differently on
// identical input is worse than one that answers wrongly, because the wrong answer can at
// least be investigated.
func match(c *ir.Call, shape model.CallShape) (string, bool) {
	// A qualified shape says nothing at all unless its qualifier holds. Cookie
	// attributes are judged against what the cookie carries, and the name in argument
	// zero is the only evidence of that available at the call.
	for _, q := range shape.Qualifiers {
		if !q.Holds(c.ArgLiterals) {
			return "", false
		}
	}
	if shape.RequiredKeyword != "" {
		return matchAbsent(c, shape)
	}
	// A positional argument that was never supplied. The count of arguments is the whole
	// evidence, so a call the frontend could not count is not judged.
	if shape.MissingArg != nil {
		if c.ArgCount > *shape.MissingArg {
			return "", false
		}
		return callName(c), true
	}
	// A call that is a defect by existing has no argument to look at.
	if shape.Always {
		return callName(c), true
	}
	// A named option rather than a position.
	if shape.Keyword != "" {
		want := strings.ToLower(shape.Keyword)
		for i, lit := range c.ArgLiterals {
			if i >= 0 {
				continue
			}
			key, value, cut := strings.Cut(lit, "=")
			if !cut || !keyIs(key, want) {
				continue
			}
			// The key was read and the value was not written down. An absence rule wants
			// to know the option is set; a rule about its VALUE has nothing to look at.
			if value == ir.UnknownLiteral {
				continue
			}
			if shape.Matches(value) {
				return lit, true
			}
		}
		return "", false
	}
	if shape.ArgIndex >= 0 {
		lit, ok := c.ArgLiterals[shape.ArgIndex]
		if ok && shape.Matches(lit) {
			return lit, true
		}
		return "", false
	}
	// Deterministic: the keys are visited in a fixed order.
	keys := make([]int, 0, len(c.ArgLiterals))
	for i := range c.ArgLiterals {
		if i < 0 {
			keys = append(keys, i)
		}
	}
	sort.Ints(keys)
	for _, k := range keys {
		if lit := c.ArgLiterals[k]; shape.Matches(lit) {
			return lit, true
		}
	}
	return "", false
}

// matchAbsent reports a required option that this call does not set.
//
// The precondition is the whole rule. `res.cookie('jwt', t, getCookieOpts())` sets
// attributes this frontend cannot see, and treating that as absence produced four false
// positives in a single production file the first time it was tried. So absence is
// claimed only where the keys were actually enumerated, or where no options were passed
// at all -- which is the one case where "it does not set this" is simply true.
func matchAbsent(c *ir.Call, shape model.CallShape) (string, bool) {
	// Further arguments whose keys must also have been read. A payload built by another
	// function says nothing about whether it contains an expiry.
	for _, idx := range shape.AlsoEnumerated {
		if !c.OptionsEnumerated(idx) {
			return "", false
		}
	}
	knowable := c.OptionsEnumerated(shape.OptionsArg)
	if shape.OptionsArg >= 0 && !c.HasArg(shape.OptionsArg) {
		// A rule that needs the options written down says nothing about a call that has
		// none: the setting may live somewhere else in that call entirely.
		if shape.OptionsMustBeWritten {
			return "", false
		}
		knowable = true
	}
	if !knowable {
		return "", false
	}

	// One key names the rule; a widened rule accepts any of several spellings of the
	// same decision, and the absence is only claimed when none of them is there.
	wanted := shape.RequiredAnyOf
	if len(wanted) == 0 {
		wanted = []string{shape.RequiredKeyword}
	}
	for i, lit := range c.ArgLiterals {
		if i >= 0 {
			continue
		}
		key, _, ok := strings.Cut(lit, "=")
		if !ok {
			continue
		}
		for _, want := range wanted {
			if keyIs(key, strings.ToLower(want)) {
				return "", false
			}
		}
	}
	return "no " + shape.RequiredKeyword, true
}

// callName is how a call is named when the finding is about the call itself rather than
// about anything passed to it.
func callName(c *ir.Call) string {
	if c.Callee.Symbol != "" {
		return c.Callee.Symbol + "()"
	}
	return c.Method + "()"
}

func finding(ix *ir.Index, fn *ir.Function, c *ir.Call, shape model.CallShape, lit string) taint.Finding {
	name := c.Callee.Symbol
	if name == "" {
		name = c.Method
	}

	return taint.Finding{
		Analysis:     shape.ID,
		DataClass:    "written-argument",
		ChannelID:    shape.ID,
		Class:        shape.Finding,
		CWE:          shape.CWE,
		Message:      shape.Reason,
		SinkLoc:      c.Loc,
		SinkSymbol:   name,
		SinkArgIndex: shape.ArgIndex,
		InTestModule: ix.InTestModule(c.Loc),
		SinkFunction: fn.Name,
		SinkRational: shape.Rationale,
		SourceLabel:  strconv.Quote(lit),
		SourceLoc:    c.Loc,
		// What tells this call apart from its siblings, for the shapes where the
		// SourceLabel cannot: see writtenArguments.
		Discriminator: writtenArguments(c, shape),
		// The evidence is the call itself: this symbol was written with this argument.
		// Short, and complete for the claim being made (ADR-006) -- unlike a flow, there
		// is no path to walk because nothing travelled.
		Path: []taint.Hop{{
			Loc:         c.Loc,
			Description: fmt.Sprintf("%s() is called with %s", name, strconv.Quote(lit)),
			Resolution:  c.Callee.Resolution,
		}},
		// Written into the source, so the call graph has nothing to be uncertain about.
		// Confidence says how well resolution went, not how much the finding matters.
		Confidence: taint.High,
		// Whether this is a defect turns on what the result is used for, which the call
		// does not carry. Reported, never gating, and the report says why.
		DependsOnUse: shape.DependsOnUse,
		// Not an assertion over the enumerated surface (ADR-009 governs flows): a weak
		// hash in a file nothing routes to is still a weak hash. Marked anchored so that
		// it is counted and can gate, with the entry point named where one reaches it.
		EntryAnchored: true,
		EntryPoint:    enclosing(ix, fn),
	}
}

// writtenArguments is what this call was written with, for the shapes whose finding does
// not otherwise say which call it was.
//
// A shape that judges an ARGUMENT already records that argument's value as the source
// label, so its siblings differ there and this stays empty -- which matters, because an
// empty discriminator leaves the fingerprint exactly as it has always been computed and
// every verdict recorded against one of those rules keeps its key.
//
// The shapes that need it are the ones whose evidence is the call itself: `Always` says a
// call is a defect by existing, and `MissingArg` says an argument was never supplied.
// Both record the SYMBOL, which is identical for every sibling. juice-shop calls
// `serveIndex` five times in one function, three of them adjudicated separately as real,
// and all of them fingerprinted alike -- `serveIndex("ftp")` and
// `serveIndex("encryptionkeys")` publish different directories and are different defects.
//
// The arguments and not the line, because surviving a reformat is the whole point
// (ADR-014). Two calls written identically in one function still share a fingerprint,
// which is correct: nothing about them differs except where they sit.
func writtenArguments(c *ir.Call, shape model.CallShape) string {
	if !shape.Always && shape.MissingArg == nil {
		return ""
	}
	if len(c.ArgLiterals) == 0 {
		return ""
	}
	indexes := make([]int, 0, len(c.ArgLiterals))
	for i := range c.ArgLiterals {
		indexes = append(indexes, i)
	}
	// Ordered, because Go randomizes map iteration and a fingerprint that changes
	// between runs on identical input is worse than one that is too coarse.
	sort.Ints(indexes)
	parts := make([]string, 0, len(indexes))
	for _, i := range indexes {
		parts = append(parts, strconv.Itoa(i)+"="+c.ArgLiterals[i])
	}
	return strings.Join(parts, ",")
}

func enclosing(ix *ir.Index, fn *ir.Function) string {
	if ep, ok := ix.EntryByFunc[fn.ID]; ok {
		if m, p := ep.Detail["method"], ep.Detail["path"]; m != "" && p != "" {
			return m + " " + p
		}
	}
	return fn.Name + "()"
}
