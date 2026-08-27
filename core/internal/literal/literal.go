// Package literal finds weaknesses visible in a written-down value and nothing else.
//
// The engine's sixth analysis kind, and the smallest. A flow asks where a value came from;
// a call shape asks what a call was written with; a store asks where a value was put.
// None of them can express an RSA private key sitting in a constant, because it is not an
// argument, it is not written into anything, and nothing reaches it. It is simply there,
// and being there is the whole of the defect.
//
// This is the kind with the least room to be wrong and the least room to be clever, and it
// is deliberately kept that way. A rule here is a shape a value either has or does not:
// `AKIA` followed by sixteen upper-case characters is an AWS key identifier and nothing
// else is. There is no entropy heuristic, no proximity to a variable named `secret`, and
// no scoring -- every one of those is a way of guessing, and a scanner that guesses about
// secrets is a scanner nobody reads twice.
//
// What that costs is real and is worth naming: a key with no recognisable shape -- a
// random thirty-character password in a constant -- is invisible here. It is caught, if at
// all, by the store and call-shape rules that watch where a literal is PUT. Silence about
// what cannot be recognised is the point (ADR-003).
package literal

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// Analyze reports every literal in the program whose own shape is a defect.
func Analyze(d *ir.IR, m model.Model) []taint.Finding {
	if len(m.Literals) == 0 {
		return nil
	}
	ix := ir.NewIndex(d)
	roles := newRoleFinder(ix, m)

	var out []taint.Finding
	for _, rule := range m.Literals {
		if rule.RegexCaptureArity {
			out = append(out, regexCaptureFindings(d, ix, rule)...)
		}
	}
	for _, fn := range d.Functions {
		// The raw value is used only as an in-memory identity. SourceLabel is deliberately
		// elided so reports do not publish a credential, and grouping by that prefix would
		// merge different keys that happen to begin alike.
		seen := make(map[string]int)
		for _, v := range fn.Values {
			if v.Kind != ir.ValueLiteral || v.Literal == "" {
				continue
			}
			text := strings.TrimSpace(v.Literal)
			// A regular expression is lowered as a literal because a rule needs its
			// text, and it is not a value the program HOLDS -- it is a description of
			// values it will recognise. `const marker = /-----BEGIN PRIVATE KEY-----/`
			// finds a key; it is not one, and reporting it would gate a build over a
			// scanner's own detector.
			if isRegexLiteral(text) {
				continue
			}
			// A fixture is not a leak. Test modules produced 34 of 59 hardcoded-secret
			// findings across ten repositories and an independent reader judged every
			// one of them false, but suppressing test files wholesale would throw away
			// the case that matters most: a REAL key committed to a test is in the
			// repository and in its history, and that is exactly how credentials leak.
			//
			// So the bar rises rather than closing. In a test module a value must not
			// look like a placeholder, and a placeholder is recognisable: it points at a
			// domain reserved for documentation, or its secret half is the word
			// "password".
			inTest := ix.InTestModule(v.Loc)
			if inTest && IsPlaceholder(text) {
				continue
			}
			for _, rule := range m.Literals {
				if !rule.Matches(text) {
					continue
				}
				// The question the shape cannot answer: does THIS program rely on the
				// value being secret? A literal the program only ever hands to somebody
				// else's service to say which client it is is that service's public
				// configuration, and there is no door here that it opens. See role.go
				// -- and note that a value with no visible role is still reported,
				// because a key in a repository is in every clone of it whatever reads
				// it.
				if r, _ := roles.classify(fn, v, text); r == rolePresented {
					break
				}
				key := rule.ID + "\x00" + text
				if at, ok := seen[key]; ok {
					out[at].RelatedSites = append(out[at].RelatedSites, taint.Site{
						Loc: v.Loc,
						Path: []taint.Hop{{
							Loc:         v.Loc,
							Description: fmt.Sprintf("%s is also written here", rule.Finding),
							Resolution:  ir.Resolved,
						}},
					})
					break
				}
				seen[key] = len(out)
				out = append(out, finding(ix, fn, v, rule, text))
				// One value is one finding. A private key that also parses as something
				// else is still one key written into one file, and reporting it twice
				// would say the file holds two.
				break
			}
		}
	}
	return out
}

// regexCaptureFindings reports only the statically impossible half of capture access: an
// index larger than the number of groups written in a regex literal. Whether an in-range
// access checked that the match succeeded is a control-flow question and is deliberately
// left out; this proof needs neither inference nor a guess about which branch runs.
func regexCaptureFindings(d *ir.IR, ix *ir.Index, rule model.LiteralRule) []taint.Finding {
	var out []taint.Finding
	for _, fn := range d.Functions {
		byID := make(map[string]*ir.Value, len(fn.Values))
		for _, v := range fn.Values {
			byID[v.ID] = v
		}
		for _, c := range fn.Calls {
			pattern := regexPatternValue(c, byID)
			if pattern == nil || !isRegexLiteral(strings.TrimSpace(pattern.Literal)) {
				continue
			}
			groups := captureCount(pattern.Literal)
			for _, v := range fn.Values {
				index, ok := captureIndex(v)
				if !ok || index <= groups || !assignedAtUse(fn, c.ResultID, v.Base, v.Loc) ||
					ambiguousUnmodelledUse(fn, v) {
					continue
				}
				out = append(out, regexCaptureFinding(ix, fn, pattern, v, groups, rule))
			}
		}
	}
	return out
}

// ambiguousUnmodelledUse declines when a read sits in control flow the frontend does not
// model and the local has several definitions. PDF.js reuses `m` for four regexes, then
// assigns a fifth result in a while condition the IR cannot state. Selecting the last
// visible definition produced one false result; treating all definitions as live produced
// ten. With no defensible reaching definition, silence is the precision-preserving answer.
func ambiguousUnmodelledUse(fn *ir.Function, access *ir.Value) bool {
	unpositioned := false
	for _, f := range fn.Flows {
		if f.Kind == "property" && f.To == access.ID && f.Block == "" {
			unpositioned = true
			break
		}
	}
	if !unpositioned {
		return false
	}
	definitions := 0
	for _, f := range fn.Flows {
		if f.Kind == "assign" && f.To == access.Base && locAtOrBefore(f.Loc, access.Loc) {
			definitions++
		}
	}
	return definitions > 1
}

func regexPatternValue(c *ir.Call, byID map[string]*ir.Value) *ir.Value {
	switch c.Method {
	case "exec":
		return byID[c.ReceiverID]
	case "match":
		for _, a := range c.Args {
			if a.Index == 0 {
				return byID[a.ValueID]
			}
		}
	}
	return nil
}

// assignedAtUse follows the definition that most recently reached each local before the
// indexed read. The TypeScript IR deliberately reuses one value for `m` across `m = re1`
// and `m = re2`; treating every incoming edge as simultaneously live made an early
// one-capture regex appear to feed later `m[3]` reads. PDF.js produced ten false findings
// from that merge, all removed by asking which assignment is actually in force here.
func assignedAtUse(fn *ir.Function, start, base string, use ir.Loc) bool {
	if start == "" || base == "" {
		return false
	}
	cur, before := base, use
	seen := map[string]bool{}
	for hops := 0; hops < 16 && cur != "" && !seen[cur]; hops++ {
		if cur == start {
			return true
		}
		seen[cur] = true
		var latest *ir.Flow
		for i := range fn.Flows {
			f := &fn.Flows[i]
			if f.Kind != "assign" || f.To != cur || !locAtOrBefore(f.Loc, before) {
				continue
			}
			if latest == nil || locAtOrBefore(latest.Loc, f.Loc) {
				latest = f
			}
		}
		if latest == nil {
			return false
		}
		cur, before = latest.From, latest.Loc
	}
	return false
}

func locAtOrBefore(a, b ir.Loc) bool {
	if a.File != b.File {
		return false
	}
	return a.Line < b.Line || (a.Line == b.Line && a.Column <= b.Column)
}

func captureIndex(v *ir.Value) (int, bool) {
	if v == nil || len(v.Path) < 3 || v.Path[0] != '[' || v.Path[len(v.Path)-1] != ']' {
		return 0, false
	}
	n, err := strconv.Atoi(v.Path[1 : len(v.Path)-1])
	return n, err == nil && n >= 0
}

// captureCount reads JavaScript's group syntax without trying to execute the pattern.
// Escaped parentheses and parentheses inside a character class are text; `(?:...)` and
// lookarounds do not capture; `(?<name>...)` does, while `(?<=...)` and `(?<!...)` do not.
func captureCount(literal string) int {
	literal = strings.TrimSpace(literal)
	end := strings.LastIndexByte(literal, '/')
	if len(literal) < 2 || literal[0] != '/' || end <= 0 {
		return 0
	}
	pattern := literal[1:end]
	groups, escaped, inClass := 0, false, false
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '[' {
			inClass = true
			continue
		}
		if ch == ']' && inClass {
			inClass = false
			continue
		}
		if ch != '(' || inClass {
			continue
		}
		if i+1 >= len(pattern) || pattern[i+1] != '?' {
			groups++
			continue
		}
		if i+2 < len(pattern) && pattern[i+2] == '<' &&
			(i+3 >= len(pattern) || (pattern[i+3] != '=' && pattern[i+3] != '!')) {
			groups++
		}
	}
	return groups
}

func regexCaptureFinding(ix *ir.Index, fn *ir.Function, pattern, access *ir.Value, groups int, rule model.LiteralRule) taint.Finding {
	return taint.Finding{
		Analysis:      rule.ID,
		DataClass:     "regex-literal",
		ChannelID:     rule.ID,
		Class:         rule.Finding,
		CWE:           rule.CWE,
		Message:       rule.Reason,
		Confidence:    taint.High,
		SourceLoc:     pattern.Loc,
		SourceLabel:   strconv.Quote(pattern.Literal),
		SinkLoc:       access.Loc,
		SinkFunction:  fn.Name,
		SinkSymbol:    access.Path,
		SinkRational:  rule.Rationale,
		InTestModule:  ix.InTestModule(access.Loc),
		EntryAnchored: true,
		EntryPoint:    enclosing(ix, fn),
		Path: []taint.Hop{
			{Loc: pattern.Loc, Description: fmt.Sprintf("pattern defines %d capture group(s)", groups), Resolution: ir.Resolved},
			{Loc: access.Loc, Description: fmt.Sprintf("reads capture %s", access.Path), Resolution: ir.Resolved},
		},
	}
}

func finding(ix *ir.Index, fn *ir.Function, v *ir.Value, rule model.LiteralRule, text string) taint.Finding {
	return taint.Finding{
		Analysis:     rule.ID,
		DataClass:    "written-value",
		ChannelID:    rule.ID,
		Class:        rule.Finding,
		CWE:          rule.CWE,
		Message:      rule.Reason,
		SinkLoc:      v.Loc,
		SinkSymbol:   rule.ID,
		SinkFunction: fn.Name,
		SinkRational: rule.Rationale,
		SourceLabel:  strconv.Quote(elide(text)),
		SourceLoc:    v.Loc,
		InTestModule: ix.InTestModule(v.Loc),
		// The evidence is the value. There is no path to walk because nothing travelled,
		// and no call to name because none was made (ADR-006).
		Path: []taint.Hop{{
			Loc:         v.Loc,
			Description: fmt.Sprintf("%s is written here", rule.Finding),
			Resolution:  ir.Resolved,
		}},
		// Written into the source, so nothing about the call graph bears on it.
		Confidence: taint.High,
		// Whether this weighs anything can turn on something the value does not carry.
		DependsOnUse: rule.DependsOnUse,
		// Like a call shape, this is an assertion about a line of code rather than over
		// the enumerated surface: a key in a file nothing routes to is still in the
		// repository, and the clone that leaks it will not care which route reached it.
		EntryAnchored: true,
		EntryPoint:    enclosing(ix, fn),
	}
}

// isRegexLiteral reports whether this is a JavaScript regular expression literal rather
// than a value. `/x/`, `/x/gi` -- slash-delimited, with only flag letters after the last
// slash.
func isRegexLiteral(text string) bool {
	if len(text) < 2 || text[0] != '/' {
		return false
	}
	end := strings.LastIndexByte(text, '/')
	if end == 0 {
		return false
	}
	for _, c := range text[end+1:] {
		if !strings.ContainsRune("dgimsuvy", c) {
			return false
		}
	}
	return true
}

// elide keeps a finding readable and keeps the secret out of the report. Enough of the
// value to recognise which one it is, and not enough to use.
func elide(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", "")
	if len(s) <= 24 {
		return s
	}
	return s[:24] + "..."
}

func enclosing(ix *ir.Index, fn *ir.Function) string {
	if ep, ok := ix.EntryByFunc[fn.ID]; ok {
		if m, p := ep.Detail["method"], ep.Detail["path"]; m != "" && p != "" {
			return m + " " + p
		}
	}
	return ""
}

// IsPlaceholder reports whether a value is standing in for a secret rather than being one.
//
// Applied only inside test modules, and deliberately so. A placeholder in production
// configuration is a different judgement -- somebody may have shipped `changeme` as a real
// signing key -- and this function has no opinion about that.
//
// The two signals are the ones the corpus actually produced. Every false
// hardcoded-credential finding in a test file across ten repositories was one or both:
//
//	"http://user:pass@example.org:80"       reserved domain AND placeholder secret
//	"http://user:pass@example.dummytld:80"  a hostname invented to be obviously invalid
//	"postgres://user:password@localhost"    the secret is the word for a secret
func IsPlaceholder(text string) bool {
	low := strings.ToLower(text)

	// The prefix is checked FIRST and it is final. A value wearing the shape of a real
	// key is a real key, whatever words happen to be inside it -- and the words are a
	// trap: AWS's own documentation constant is `AKIAIOSFODNN7EXAMPLE`, and checking for
	// "example" before the prefix would have suppressed `sk_live_test_...` along with it.
	//
	// This deliberately catches AWS's documentation constant. Nothing about the shape of
	// a key distinguishes a published example from a live credential, and the two
	// mistakes do not cost the same.
	for _, pfx := range []string{
		"sk_live_", "sk_test_", "pk_live_", "rk_live_", "akia", "asia", "ghp_", "gho_",
		"ghs_", "github_pat_", "xoxb-", "xoxp-", "xapp-", "glpat-", "npm_", "shpat_",
		"-----begin",
	} {
		if strings.HasPrefix(low, pfx) {
			return false
		}
	}

	// Domains reserved for documentation and testing (RFC 2606, RFC 6761). A value
	// pointing at one was written to be read, not to be used.
	for _, d := range []string{
		"example.com", "example.org", "example.net", "example.edu", ".example",
		".invalid", ".localhost", "localhost", "127.0.0.1", "::1",
		".test", "dummytld", "yourdomain", "your-domain", "mydomain",
	} {
		if strings.Contains(low, d) {
			return true
		}
	}

	// The secret half of a credential URL, when it is the WORD for a secret rather than
	// a secret. Read from the last colon-separated field before the host, which is where
	// `scheme://user:pass@host` keeps it.
	if at := strings.Index(low, "@"); at > 0 {
		cred := low[:at]
		if i := strings.LastIndex(cred, ":"); i >= 0 {
			switch strings.TrimSpace(cred[i+1:]) {
			case "pass", "password", "passwd", "secret", "changeme", "test", "dummy",
				"placeholder", "redacted", "xxx", "xxxx", "foo", "bar", "hunter2",
				"123456", "12345678", "admin", "root", "example", "fake", "none":
				return true
			}
		}
	}

	// A value written to stand in for a secret says so, in a word. These are the ones the
	// corpus produced: `"not hex"`, `"abc123"`, `"test_password"`,
	// `"route-send-test-secret"`.
	for _, w := range []string{
		"test", "dummy", "fake", "sample", "example", "placeholder", "changeme",
		"notreal", "not hex", "invalid", "foo", "bar", "baz", "abc123", "hunter2",
		"password", "secret-key-for", "mysecret", "supersecret", "topsecret",
	} {
		if strings.Contains(low, w) {
			return true
		}
	}

	// Length is the last signal, and it only speaks inside a test module. A credential
	// worth leaking is long: an API key, a token, a hex digest. Something short enough to
	// type from memory is something a person typed to make a test pass.
	return len(text) < 20
}
