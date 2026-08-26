package model

import "strings"

// A small parser for regular-expression syntax, enough to answer one question: can two
// repetitions in this pattern claim the same input?
//
// The byte scanner in redos.go answers that for NESTING -- `(a+)+`, `(a|a)*` -- by asking
// whether a repeated body begins with something that must match exactly once. That test is
// local to the group, and there is a shape it gets wrong: the marker at the front of the
// body can be defeated by what sits BESIDE the group.
//
//	[a-z0-9-_]+(-[a-z0-9-_]+)*
//
// Every repetition of the group has to begin with a hyphen, so read alone the group is
// unambiguous. But the `+` in front of it matches hyphens too -- `-` is in that class --
// so a run like `a-a-a-a` can be divided between the two in as many ways as it has
// hyphens, and a backtracking engine tries all of them. This is umami's pre-authentication
// ReDoS, and the same pattern with `[a-zA-Z0-9]` in front is completely safe, so nothing
// short of reading the two character sets can tell them apart.

// charSet is the set of characters an atom can match: a bitmap over ASCII, plus one flag
// for everything above it. Overlap is all that is ever asked of it.
type charSet struct {
	ascii    [128]bool
	nonASCII bool
}

func (s *charSet) add(c byte) {
	if c < 128 {
		s.ascii[c] = true
	} else {
		s.nonASCII = true
	}
}

func (s *charSet) addRange(lo, hi byte) {
	for c := int(lo); c <= int(hi); c++ {
		s.add(byte(c))
	}
}

func (s *charSet) addAll() {
	for c := 0; c < 128; c++ {
		s.ascii[c] = true
	}
	s.nonASCII = true
}

func (s *charSet) negate() {
	for c := 0; c < 128; c++ {
		s.ascii[c] = !s.ascii[c]
	}
	s.nonASCII = !s.nonASCII
}

func (s *charSet) union(o charSet) {
	for c := 0; c < 128; c++ {
		if o.ascii[c] {
			s.ascii[c] = true
		}
	}
	s.nonASCII = s.nonASCII || o.nonASCII
}

func (s charSet) empty() bool {
	if s.nonASCII {
		return false
	}
	for c := 0; c < 128; c++ {
		if s.ascii[c] {
			return false
		}
	}
	return true
}

func (s charSet) overlaps(o charSet) bool {
	if s.nonASCII && o.nonASCII {
		return true
	}
	for c := 0; c < 128; c++ {
		if s.ascii[c] && o.ascii[c] {
			return true
		}
	}
	return false
}

// nodeKind separates the three things a repetition can be applied to. Zero-width nodes
// are kept rather than dropped because they sit BETWEEN atoms, and "what precedes this
// group" has to see past them without treating them as a separator.
type nodeKind int

const (
	nodeChar  nodeKind = iota // one character, class or escape
	nodeGroup                 // a parenthesised alternation
	nodeZero                  // an anchor or a lookaround: matches no input
)

type reNode struct {
	kind nodeKind
	set  charSet    // nodeChar
	alts [][]reNode // nodeGroup: one sequence per branch

	// How the quantifier on this node behaves. `unbounded` is the only kind that can
	// make two repetitions compete for the same input: a fixed count has one way to
	// match and `?` has two.
	unbounded bool
	optional  bool
}

// parseRegex reads a pattern into alternatives of sequences. It is deliberately partial:
// anything it cannot read makes it give up, and giving up means the caller says nothing
// rather than guessing.
func parseRegex(pattern string) ([][]reNode, bool) {
	p := strings.TrimPrefix(pattern, "/")
	if i := strings.LastIndexByte(p, '/'); i > 0 && isFlags(p[i+1:]) {
		p = p[:i] // drop the flags of a JavaScript literal
	}
	pos := 0
	alts, ok := parseAlts(p, &pos)
	if !ok || pos != len(p) {
		return nil, false
	}
	return alts, true
}

func isFlags(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("dgimsuvy", c) {
			return false
		}
	}
	return true
}

func parseAlts(p string, pos *int) ([][]reNode, bool) {
	var alts [][]reNode
	for {
		seq, ok := parseSeq(p, pos)
		if !ok {
			return nil, false
		}
		alts = append(alts, seq)
		if *pos < len(p) && p[*pos] == '|' {
			*pos++
			continue
		}
		return alts, true
	}
}

func parseSeq(p string, pos *int) ([]reNode, bool) {
	seq := []reNode{}
	for *pos < len(p) && p[*pos] != '|' && p[*pos] != ')' {
		n, ok := parseAtom(p, pos)
		if !ok {
			return nil, false
		}
		readQuantifier(p, pos, &n)
		seq = append(seq, n)
	}
	return seq, true
}

func parseAtom(p string, pos *int) (reNode, bool) {
	i := *pos
	switch c := p[i]; c {
	case '(':
		*pos++
		zero := false
		if *pos < len(p) && p[*pos] == '?' {
			kind, ok := skipGroupPrefix(p, pos)
			if !ok {
				return reNode{}, false
			}
			zero = kind
		}
		alts, ok := parseAlts(p, pos)
		if !ok {
			return reNode{}, false
		}
		if *pos >= len(p) || p[*pos] != ')' {
			return reNode{}, false
		}
		*pos++
		if zero {
			return reNode{kind: nodeZero}, true
		}
		return reNode{kind: nodeGroup, alts: alts}, true
	case '[':
		return parseClass(p, pos)
	case '^', '$':
		*pos++
		return reNode{kind: nodeZero}, true
	case '.':
		*pos++
		var s charSet
		s.addAll()
		s.ascii['\n'] = false
		return reNode{kind: nodeChar, set: s}, true
	case '\\':
		if i+1 >= len(p) {
			return reNode{}, false
		}
		*pos += 2
		return escapeNode(p[i+1])
	case '*', '+', '?':
		return reNode{}, false // a quantifier with nothing to quantify
	default:
		*pos++
		var s charSet
		s.add(c)
		return reNode{kind: nodeChar, set: s}, true
	}
}

// skipGroupPrefix consumes `?:`, `?=`, `?!`, `?<=`, `?<!` and `?<name>`, reporting whether
// the group matches no input. A lookaround consumes nothing, so it separates nothing.
func skipGroupPrefix(p string, pos *int) (zeroWidth bool, ok bool) {
	*pos++ // the '?'
	if *pos >= len(p) {
		return false, false
	}
	switch p[*pos] {
	case ':':
		*pos++
		return false, true
	case '=', '!':
		*pos++
		return true, true
	case '<':
		if *pos+1 < len(p) && (p[*pos+1] == '=' || p[*pos+1] == '!') {
			*pos += 2
			return true, true
		}
		end := strings.IndexByte(p[*pos:], '>')
		if end < 0 {
			return false, false
		}
		*pos += end + 1
		return false, true
	case 'P':
		end := strings.IndexByte(p[*pos:], '>')
		if end < 0 {
			return false, false
		}
		*pos += end + 1
		return false, true
	}
	return false, false
}

func parseClass(p string, pos *int) (reNode, bool) {
	i := *pos + 1
	var s charSet
	negated := false
	if i < len(p) && p[i] == '^' {
		negated = true
		i++
	}
	first := true
	for i < len(p) {
		if p[i] == ']' && !first {
			*pos = i + 1
			if negated {
				s.negate()
			}
			return reNode{kind: nodeChar, set: s}, true
		}
		first = false

		lo, width, ok := classAtom(p, i)
		if !ok {
			return reNode{}, false
		}
		// A shorthand escape is a set, not a character, and cannot be a range endpoint.
		if width < 0 {
			node, ok := escapeNode(p[i+1])
			if !ok {
				return reNode{}, false
			}
			s.union(node.set)
			i += 2
			continue
		}
		i += width
		// A hyphen forms a range only when something follows it before the bracket.
		if i+1 < len(p) && p[i] == '-' && p[i+1] != ']' {
			hi, hwidth, ok := classAtom(p, i+1)
			if !ok || hwidth < 0 {
				// `[a-\d]` is not a range; treat the hyphen as itself.
				s.add('-')
				i++
				continue
			}
			if hi < lo {
				return reNode{}, false
			}
			s.addRange(lo, hi)
			i += 1 + hwidth
			continue
		}
		s.add(lo)
	}
	return reNode{}, false
}

// classAtom reads one member of a character class, returning the character and how many
// bytes it took. A width of -1 means a shorthand escape, which stands for a whole set.
func classAtom(p string, i int) (c byte, width int, ok bool) {
	if i >= len(p) {
		return 0, 0, false
	}
	if p[i] != '\\' {
		return p[i], 1, true
	}
	if i+1 >= len(p) {
		return 0, 0, false
	}
	switch e := p[i+1]; e {
	case 'd', 'D', 'w', 'W', 's', 'S':
		return 0, -1, true
	case 'n':
		return '\n', 2, true
	case 'r':
		return '\r', 2, true
	case 't':
		return '\t', 2, true
	case 'f':
		return '\f', 2, true
	case 'v':
		return '\v', 2, true
	case 'b':
		return 8, 2, true
	case 'x', 'u', 'c', 'p', 'P', '0':
		// A numeric or unicode escape. Readable in principle and not read here; the
		// answer is silence rather than a guess.
		return 0, 0, false
	default:
		return e, 2, true
	}
}

// escapeNode turns a backslash escape into the set it matches.
func escapeNode(e byte) (reNode, bool) {
	var s charSet
	switch e {
	case 'd', 'D':
		s.addRange('0', '9')
	case 'w', 'W':
		s.addRange('a', 'z')
		s.addRange('A', 'Z')
		s.addRange('0', '9')
		s.add('_')
	case 's', 'S':
		for _, c := range []byte{' ', '\t', '\n', '\r', '\f', '\v'} {
			s.add(c)
		}
		s.nonASCII = true // NBSP and friends
	case 'b', 'B', 'A', 'Z', 'z', 'G':
		return reNode{kind: nodeZero}, true
	case 'n':
		s.add('\n')
	case 'r':
		s.add('\r')
	case 't':
		s.add('\t')
	case 'f':
		s.add('\f')
	case 'v':
		s.add('\v')
	case 'x', 'u', 'c', 'p', 'P', 'k':
		return reNode{}, false
	default:
		if e >= '0' && e <= '9' {
			return reNode{}, false // a backreference matches whatever the group did
		}
		s.add(e)
	}
	if e == 'D' || e == 'W' || e == 'S' {
		s.negate()
	}
	return reNode{kind: nodeChar, set: s}, true
}

func readQuantifier(p string, pos *int, n *reNode) {
	if *pos >= len(p) {
		return
	}
	switch p[*pos] {
	case '*':
		n.unbounded, n.optional = true, true
		*pos++
	case '+':
		n.unbounded = true
		*pos++
	case '?':
		n.optional = true
		*pos++
	case '{':
		end := strings.IndexByte(p[*pos:], '}')
		if end < 0 {
			return
		}
		body := p[*pos+1 : *pos+end]
		if !isCount(body) {
			return // `{` used as a literal brace
		}
		n.unbounded = unboundedBrace(p, *pos)
		n.optional = strings.HasPrefix(body, "0,") || body == "0"
		*pos += end + 1
	default:
		return
	}
	// A lazy or possessive marker changes the order the engine tries alternatives, not
	// how many there are.
	if *pos < len(p) && (p[*pos] == '?' || p[*pos] == '+') {
		*pos++
	}
}

func isCount(body string) bool {
	if body == "" {
		return false
	}
	for i := 0; i < len(body); i++ {
		if body[i] != ',' && (body[i] < '0' || body[i] > '9') {
			return false
		}
	}
	return true
}

// adjacentAmbiguity reports the shape the nesting test cannot see: a repetition standing
// next to a repeated group whose leading marker that repetition can also match.
//
//	[a-z0-9-_]+(-[a-z0-9-_]+)*      hyphen is IN the class -- exponential
//	[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*    hyphen is not -- linear, and extremely common
//
// Three conditions, all of them structural. The left neighbour repeats without bound. The
// group repeats without bound and has a repetition of its own inside it, so its
// repetitions vary in length -- with fixed-length repetitions the only choice is where the
// left one stopped, and there are as many of those as there are characters. And the two
// character sets meet, which is what lets one run of input be divided between them in more
// than one way.
//
// Only this direction. A repeated group followed by a repetition it overlaps is the same
// ambiguity written backwards and is a stated miss: it is rarer, and every shape this
// engine reports has to be one a reader can confirm from the pattern alone.
func adjacentAmbiguity(pattern string) bool {
	alts, ok := parseRegex(pattern)
	if !ok {
		return false
	}
	for _, seq := range alts {
		if seqHasAdjacentAmbiguity(seq) {
			return true
		}
	}
	return false
}

func seqHasAdjacentAmbiguity(seq []reNode) bool {
	for i := range seq {
		if seq[i].kind == nodeGroup {
			for _, branch := range seq[i].alts {
				if seqHasAdjacentAmbiguity(branch) {
					return true
				}
			}
		}
		if i+1 >= len(seq) {
			continue
		}
		left, right := seq[i], seq[i+1]
		if !left.unbounded || left.kind != nodeChar {
			continue
		}
		if right.kind != nodeGroup || !right.unbounded || !containsUnbounded(right.alts) {
			continue
		}
		marker, ok := leadingSet(right.alts)
		if !ok || marker.empty() {
			continue
		}
		if left.set.overlaps(marker) {
			return true
		}
	}
	return false
}

// containsUnbounded reports whether anything inside these branches repeats without bound,
// which is what makes one repetition of the group a different length from the next.
func containsUnbounded(alts [][]reNode) bool {
	for _, seq := range alts {
		for _, n := range seq {
			if n.unbounded {
				return true
			}
			if n.kind == nodeGroup && containsUnbounded(n.alts) {
				return true
			}
		}
	}
	return false
}

// leadingSet returns the characters a repetition of this group must begin with, unioned
// over its branches. It reports false when any branch can begin with nothing at all --
// that group has no marker, which is the nesting test's question rather than this one's.
func leadingSet(alts [][]reNode) (charSet, bool) {
	var out charSet
	for _, seq := range alts {
		got := false
		for _, n := range seq {
			if n.kind == nodeZero || n.optional {
				continue // matches no input, or need not match at all
			}
			switch n.kind {
			case nodeChar:
				out.union(n.set)
			case nodeGroup:
				inner, ok := leadingSet(n.alts)
				if !ok {
					return charSet{}, false
				}
				out.union(inner)
			}
			got = true
			break
		}
		if !got {
			return charSet{}, false
		}
	}
	return out, true
}
