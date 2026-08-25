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
