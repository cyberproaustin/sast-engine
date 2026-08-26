package model_test

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/model"
)

func TestCatastrophicPattern(t *testing.T) {
	catastrophic := []string{
		`(a+)*`,
		`(a|a)+`,
		`^(a+)+$`,
		`/^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+$/`,
		`^(\w+\s?)*$`,
		`(x{2,})+`,
	}
	for _, p := range catastrophic {
		if !model.CatastrophicPattern(p) {
			t.Errorf("%s should be reported: a quantified group with a quantifier inside it", p)
		}
	}

	// Every one of these repeats something, and none of them lets the engine split one
	// input between two repetitions -- which is the property that costs exponential time.
	fine := []string{
		`^[a-z0-9]+$`,
		`^\d{4}-\d{2}-\d{2}$`,
		`(foo|bar)`,
		`^https?://`,
		`[a-z]+@[a-z]+\.[a-z]{2,3}`,
		`\(\d+\)`,  // escaped parentheses are literal
		`[(+*)]+`,  // quantifiers inside a character class are literal
		`(a|b){3}`, // a fixed count cannot blow up
	}
	for _, p := range fine {
		if model.CatastrophicPattern(p) {
			t.Errorf("%s must not be reported: nothing here can be split between two repetitions", p)
		}
	}
}

// Patterns from production repositories that were reported before the body-anchoring
// test existed, and are not catastrophic. Every repetition of each has to start with a
// separator, so there is exactly one way to split any input between them.
func TestAnchoredRepetitionIsNotCatastrophic(t *testing.T) {
	for _, p := range []string{
		`^[a-zA-Z0-9]+(?:[-_:][a-zA-Z0-9]+)*$`,
		`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`,
		`^(/[a-z]+)+$`,
	} {
		if model.CatastrophicPattern(p) {
			t.Errorf("%s must not be reported: every repetition starts with a separator", p)
		}
	}

	// And the one that is. Its own file says so in a comment.
	if !model.CatastrophicPattern(`([0-9]+)+\#`) {
		t.Error(`([0-9]+)+\# must be reported: a run of digits can be split any number of ways`)
	}
}

// Two shapes an audit found the first version answering backwards.
func TestNamedGroupsAndDisjointAlternation(t *testing.T) {
	// A named group's NAME is not the start of its body. Reading it as one made this
	// look like a pattern whose repetitions are separated by the letter c.
	if !model.CatastrophicPattern(`(?<chunk>a+)+$`) {
		t.Error(`(?<chunk>a+)+$ must be reported: the name is not part of the body`)
	}
	if !model.CatastrophicPattern(`(?:a+)+$`) {
		t.Error(`(?:a+)+$ must be reported`)
	}

	// An alternation of DISTINCT single characters is a character class written the long
	// way, and there is exactly one way to match each character.
	for _, p := range []string{`(a|b)+$`, `(a|b|c)*`, `([0-9]|[a-z])+`} {
		if model.CatastrophicPattern(p) {
			t.Errorf("%s must not be reported: no two branches can claim the same input", p)
		}
	}
	// And when two branches CAN claim the same input, it can.
	if !model.CatastrophicPattern(`(a|a)+`) {
		t.Error(`(a|a)+ must be reported: both branches match the same character`)
	}
}

// A real pattern from a production repository that the first two versions of the
// anchoring test both reported. The marker is a dot, and there is optional whitespace in
// front of it -- which changes nothing, because every repetition still has to see one.
func TestOptionalPrefixDoesNotHideTheMarker(t *testing.T) {
	for _, p := range []string{
		`\{\{\s*\$json((?:\s*\.\s*[a-zA-Z_$][\w$]*)+)\s*\}\}`,
		`(?:\s*,\s*[a-z]+)*`,
		`(?:-?[0-9]+)+`, // an optional sign, then digits that repeat -- still a marker? no
	}[:2] {
		if model.CatastrophicPattern(p) {
			t.Errorf("%s must not be reported: every repetition has to see its separator", p)
		}
	}
	// And a body with nothing mandatory in it at all can blow up, optional prefix or not.
	for _, p := range []string{`(\s*[a-z]*)+`, `^(\w+\s?)*$`} {
		if !model.CatastrophicPattern(p) {
			t.Errorf("%s must be reported: nothing in the body has to match exactly once", p)
		}
	}
}

// The second shape, and the reason it needs a parse rather than a scan.
//
// Both of these repeat a class and then repeat a hyphen-separated group of the same class.
// They differ by one character, and the difference decides whether a hyphenated run can be
// divided between the two repetitions in exponentially many ways. Nothing about the
// nesting separates them -- the group's body begins with a marker in both -- so the only
// thing that can is reading what the two character sets hold.
func TestAdjacentRepetitionsThatOverlap(t *testing.T) {
	catastrophic := []string{
		`[a-z0-9-_]+(-[a-z0-9-_]+)*`, // umami's, reduced
		`^[\w-]+(-[\w]+)*$`,          // \w and a hyphen in one class
		`/^(localhost(:[1-9]\d{0,4})?|((?=[a-z0-9-_]{1,63}\.)(xn--)?[a-z0-9-_]+(-[a-z0-9-_]+)*\.)+(xn--)?[a-z0-9-_]{2,63})$/`, // umami's, whole
	}
	for _, p := range catastrophic {
		if !model.CatastrophicPattern(p) {
			t.Errorf("%s should be reported: the class in front of the group matches the group's own separator", p)
		}
	}

	// The commonest validation patterns there are, and every one of them is linear
	// because the separator the group repeats on is not in the class before it.
	fine := []string{
		`^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$`,
		`\w+([-.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*`,
		`[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*`,
		`^[a-z]+(/[a-z]+)*$`,
		`^\d+(,\d+)*$`,
	}
	for _, p := range fine {
		if model.CatastrophicPattern(p) {
			t.Errorf("%s must not be reported: the group's separator is not in the class before it", p)
		}
	}
}

// A group whose repetitions are all the same length gives one choice -- where the
// repetition in front of it stopped -- and there are as many of those as there are
// characters. Linear, and excluded on purpose.
func TestFixedLengthRepetitionsAreNotAmbiguous(t *testing.T) {
	for _, p := range []string{
		`[a-f0-9-]+(-[a-f0-9]{4})*`,
		`[a-z-]+(-ab)*`,
	} {
		if model.CatastrophicPattern(p) {
			t.Errorf("%s must not be reported: every repetition of the group is the same length", p)
		}
	}
}

// A pattern the parser cannot read produces silence, not a guess. Backreferences and
// numeric escapes are the two shapes it declines.
func TestUnreadablePatternsSayNothing(t *testing.T) {
	for _, p := range []string{
		`([a-z-]+)-\1+`,
		`[\x41-\x5a-]+(-[\x41-\x5a]+)*`,
	} {
		if model.CatastrophicPattern(p) {
			t.Errorf("%s must not be reported: the parser cannot read it and does not guess", p)
		}
	}
}

// The Python spellings of the same two shapes. A pattern is an ordinary string there, so
// nothing about the syntax that reaches this function differs -- which is the point: the
// test is on the pattern, and the language decides only how the pattern is written down.
func TestPythonPatternSpellings(t *testing.T) {
	if !model.CatastrophicPattern(`^(\s*\w+)+$`) {
		t.Error(`^(\s*\w+)+$ must be reported: nothing in the body has to match exactly once`)
	}
	if !model.CatastrophicPattern(`^[\w-]+(-\w+)*$`) {
		t.Error(`^[\w-]+(-\w+)*$ must be reported: the hyphen is in the class in front of the group`)
	}
	if model.CatastrophicPattern(`^\w+(-\w+)*$`) {
		t.Error(`^\w+(-\w+)*$ must not be reported: \w holds no hyphen`)
	}
}
