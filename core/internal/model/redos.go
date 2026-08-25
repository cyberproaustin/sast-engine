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
// try to be: everything it reports has the nesting, and a pattern that backtracks for
// some subtler reason is a stated miss. What it must not do is guess, because the rule
// it feeds fires on a real input reaching a real call.
func CatastrophicPattern(pattern string) bool {
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
	if i < len(p) && p[i] == '?' {
		i++
		for i < len(p) && p[i] != '>' && (p[i] == ':' || p[i] == '=' || p[i] == '!' || p[i] == '<' || p[i] == 'P') {
			if p[i] == ':' || p[i] == '=' || p[i] == '!' {
				return i + 1
			}
			i++
		}
		if i < len(p) && p[i] == '>' {
			return i + 1
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
	if body == "" || topLevelAlternation(body) {
		// An alternation gives the body more than one way in, so whatever the first
		// branch starts with says nothing about the others. `(a|a)+` is the smallest
		// catastrophic pattern there is and it starts with a plain literal.
		return false
	}
	i := 0
	switch body[0] {
	case '\\':
		i = 2
	case '[':
		end := strings.IndexByte(body, ']')
		if end < 1 {
			return false
		}
		i = end + 1
	case '(', '|', '^', '.':
		// A group, an alternation, an anchor or "any character" says nothing about where
		// one repetition ends.
		return false
	default:
		i = 1
	}
	if i >= len(body) {
		return true
	}
	// Quantified or optional, so it is not a marker after all.
	switch body[i] {
	case '?', '*', '+', '{':
		return false
	}
	return true
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
