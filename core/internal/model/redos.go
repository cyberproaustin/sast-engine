package model

import "strings"

// CatastrophicPattern reports whether a regular expression can be made to backtrack
// exponentially -- the property that turns a validation check into a way to stop the
// process by sending it a long string.
//
// The shape is a QUANTIFIED GROUP whose body is itself quantified or alternated:
// `(a+)*`, `(a|a)+`, `(([\-.]|[_]+)?([a-zA-Z0-9]+))*`. Each of those lets the engine
// split the same input between the inner and outer repetition in exponentially many
// ways, and a backtracking engine tries all of them before giving up. The last one is a
// real email pattern out of a vulnerable application, and it is the shape most email
// patterns on the internet have.
//
// Deliberately structural and deliberately narrow. It is not a decision procedure --
// that question is undecidable in general and expensive in practice -- and it does not
// try to be: everything it reports has one of the two shapes, and a pattern that
// backtracks for some subtler reason is a stated miss. What it must not do is guess,
// because the rule it feeds fires on a real input reaching a real call.
func CatastrophicPattern(pattern string) bool {
	return nestedAmbiguity(pattern) || adjacentAmbiguity(pattern)
}

// nestedAmbiguity is the first shape: a quantified group whose repetitions have no marker
// to tell one from the next. Scanned byte by byte rather than parsed, because the question
// it asks is local to a group and needs nothing the scanner cannot see.
func nestedAmbiguity(pattern string) bool {
	p := strings.TrimPrefix(pattern, "/")
	if i := strings.LastIndexByte(p, '/'); i > 0 {
		p = p[:i] // drop the flags of a JavaScript literal
	}

	// Per open group: where its body starts, and whether the body has held a quantifier
	// or an alternation.
	type group struct {
		body  int
		risky bool
	}
	var stack []*group
	inClass := false

	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == '\\':
			i++ // whatever follows is a literal, including a bracket
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
		case c == '(':
			stack = append(stack, &group{body: bodyStart(p, i)})
		case c == ')':
			if len(stack) == 0 {
				continue
			}
			closed := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			// A quantifier ON this group, with something repeatable inside it -- and no
			// separator at the front of the body to say where one repetition ended and
			// the next began.
			if closed.risky && repeats(p, i+1) && !anchored(p[closed.body:i]) {
				return true
			}
			// A group that was risky stays risky for whatever encloses it: the nesting
			// that matters can be two levels apart.
			if len(stack) > 0 && (closed.risky || repeats(p, i+1)) {
				stack[len(stack)-1].risky = true
			}
		case c == '|':
			if len(stack) > 0 {
				stack[len(stack)-1].risky = true
			}
		case c == '*' || c == '+' || c == '{':
			if c == '{' && !unboundedBrace(p, i) {
				continue
			}
			if len(stack) > 0 {
				stack[len(stack)-1].risky = true
			}
		}
	}
	return false
}

// bodyStart skips the `?:`, `?=`, `?<name>` and similar prefixes of a group, returning
// where its actual body begins.
func bodyStart(p string, open int) int {
	i := open + 1
	if i >= len(p) || p[i] != '?' {
		return i
	}
	i++
	if i >= len(p) {
		return i
	}
	switch p[i] {
	case ':', '=', '!':
		return i + 1
	case '<', 'P':
		// A NAME, which runs to the closing angle bracket -- and a lookbehind, whose
		// `<=` and `<!` are two characters. Scanning to the `>` covers both, and not
		// scanning to it read `(?<chunk>a+)+` as a body beginning with the letter c,
		// which looks like a separator and made a catastrophic pattern read as safe.
		if end := strings.IndexByte(p[i:], '>'); end >= 0 {
			return i + end + 1
		}
		if i+1 < len(p) && (p[i+1] == '=' || p[i+1] == '!') {
			return i + 2
		}
	}
	return i
}

// topLevelAlternation reports whether a body offers a choice at its own level.
func topLevelAlternation(body string) bool {
	depth, inClass := 0, false
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c == '\\':
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == '|' && depth == 0:
			return true
		}
	}
	return false
}

// distinctSingleCharacters reports whether every top-level branch of an alternation is
// one character (or one class) and no two of them are the same.
func distinctSingleCharacters(body string) bool {
	seen := map[string]bool{}
	depth, inClass, start := 0, false, 0
	branch := func(end int) bool {
		b := body[start:end]
		if !singleAtom(b) || seen[b] {
			return false
		}
		seen[b] = true
		return true
	}
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c == '\\':
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == '|' && depth == 0:
			if !branch(i) {
				return false
			}
			start = i + 1
		}
	}
	return branch(len(body))
}

// singleAtom reports whether a branch is exactly one character, one escape or one class,
// with no quantifier on it.
func singleAtom(b string) bool {
	switch {
	case b == "":
		return false
	case b[0] == '\\':
		return len(b) == 2
	case b[0] == '[':
		end := strings.IndexByte(b, ']')
		return end == len(b)-1
	case b[0] == '(' || b[0] == '.' || b[0] == '^' || b[0] == '$':
		return false
	}
	return len(b) == 1
}

// anchored reports whether a repeated body BEGINS with something that must match exactly
// once -- a literal, or a character class with no quantifier after it.
//
// That is what stops the repetitions overlapping, and it is the difference between a
// pattern that costs exponential time and one that does not. `(?:[-_:][a-zA-Z0-9]+)*`
// repeats, and every repetition has to start with a separator, so there is exactly one
// way to split any input between them. `([0-9]+)+` has no such marker: a run of digits
// can be divided between the inner and outer repetition in as many ways as it has
// characters.
//
// Two real patterns from production repositories were reported before this existed, and
// both are anchored this way. The nodegoat one that is genuinely catastrophic is not.
func anchored(body string) bool {
	if body == "" {
		return false
	}
	if topLevelAlternation(body) {
		// An alternation usually gives the body more than one way in, so whatever the
		// first branch starts with says nothing about the others -- `(a|a)+` is the
		// smallest catastrophic pattern there is and it starts with a plain literal.
		//
		// Unless the branches are single characters and all different, in which case the
		// group is a character class written the long way and there is exactly one way to
		// match each character. `(a|b)+` cannot blow up; `(a|a)+` can, and the difference
		// is whether two branches can claim the same input.
		return distinctSingleCharacters(body)
	}
	// Walk to the first atom that must match EXACTLY ONCE. An optional atom in front of
	// it changes nothing: `(?:\s*\.\s*[a-z]+)+` still has to see a dot per repetition,
	// and requiring the marker to be the very first thing reported that pattern -- which
	// is a real one out of a production repository, and is linear.
	for i := 0; i < len(body); {
		width, ok := atomWidth(body, i)
		if !ok {
			return false
		}
		switch quantifierAt(body, i+width) {
		case optional:
			i += width + quantifierWidth(body, i+width)
		case repeatable:
			// Mandatory and repeatable, which is the ambiguity itself.
			return false
		default:
			// Exactly once. Only a single character or class is a marker; a group says
			// nothing about where one repetition ended.
			return body[i] != '('
		}
	}
	return false
}

type quantifier int

const (
	once quantifier = iota
	optional
	repeatable
)

func quantifierAt(p string, i int) quantifier {
	if i >= len(p) {
		return once
	}
	switch p[i] {
	case '*', '?':
		return optional
	case '+':
		return repeatable
	case '{':
		if unboundedBrace(p, i) {
			return repeatable
		}
	}
	return once
}

func quantifierWidth(p string, i int) int {
	if i >= len(p) {
		return 0
	}
	switch p[i] {
	case '*', '?', '+':
		if i+1 < len(p) && (p[i+1] == '?' || p[i+1] == '+') {
			return 2 // lazy or possessive
		}
		return 1
	case '{':
		if end := strings.IndexByte(p[i:], '}'); end >= 0 {
			return end + 1
		}
	}
	return 0
}

// atomWidth returns the length of the atom starting here: an escape, a character class, a
// group, or one character.
func atomWidth(p string, i int) (int, bool) {
	if i >= len(p) {
		return 0, false
	}
	switch p[i] {
	case '\\':
		if i+1 >= len(p) {
			return 0, false
		}
		return 2, true
	case '[':
		for j := i + 1; j < len(p); j++ {
			if p[j] == '\\' {
				j++
				continue
			}
			if p[j] == ']' {
				return j - i + 1, true
			}
		}
		return 0, false
	case '(':
		depth := 0
		for j := i; j < len(p); j++ {
			switch p[j] {
			case '\\':
				j++
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					return j - i + 1, true
				}
			}
		}
		return 0, false
	case ')', '|':
		return 0, false
	}
	return 1, true
}

// repeats reports whether a quantifier that can match many times starts at this offset.
func repeats(p string, i int) bool {
	if i >= len(p) {
		return false
	}
	switch p[i] {
	case '*', '+':
		return true
	case '{':
		return unboundedBrace(p, i)
	}
	return false
}

// unboundedBrace reports whether `{...}` at this offset can repeat enough times to
// matter. `{2}` is a fixed count and costs nothing; `{2,}` and `{2,100}` do not.
func unboundedBrace(p string, i int) bool {
	end := strings.IndexByte(p[i:], '}')
	if end < 0 {
		return false
	}
	body := p[i+1 : i+end]
	comma := strings.IndexByte(body, ',')
	if comma < 0 {
		return false // an exact count
	}
	if comma == len(body)-1 {
		return true // `{2,}` -- unbounded
	}
	// `{2,100}` is bounded but the bound can still be large enough to hurt.
	return len(body)-comma-1 >= 2
}
