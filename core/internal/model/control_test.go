package model

import "testing"

// The rules are a list of likely names, which is the weakest kind of rule in this project.
// These cases are the ones that justify matching loosely at all: every one of them appears
// in the production corpora and none of them matched under equality.
func TestClassifyControlMatchesRealNames(t *testing.T) {
	m := Builtin()
	cases := []struct{ name, want string }{
		{"authHandler.isAuthenticated", "authentication"}, // qualified by its holder
		{"JwtAuthGuard", "authentication"},                // framework guard class
		{"ThrottlerBehindProxyGuard", "rate-limit"},       // decorated limiter
		{"requireAuth", "authentication"},
		{"RolesGuard", "authorization"},
		{"req.user", ""},        // not a control
		{"getUserById", ""},     // reads a user, does not check one
		{"bodyParser.json", ""}, // middleware, but not a control
	}
	for _, c := range cases {
		if got := m.ClassifyControl(c.name); got != c.want {
			t.Errorf("ClassifyControl(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

// Containment has to begin at a word, or it reads a control into a word that merely
// contains one.
//
// `unauthorized` is the case that forced this and it is the opposite of a control: umami
// calls it 145 times to WRITE a 401. It went unnoticed for as long as classification could
// not see a locally defined call at all; the first tree it was pointed at came back with
// 136 of 170 entry points carrying an "authorization control" that answers requests with a
// refusal. Inventing a control is a false claim about what is THERE, on the surface, which
// is the primary output (ADR-009).
func TestClassifyControlOnlyMatchesAtAWordBoundary(t *testing.T) {
	m := Builtin()
	cases := []struct{ name, want string }{
		{"unauthorized", ""},           // writes a 401; contains "authorize"
		{"sendUnauthorized", ""},       // the same, one word further in
		{"authorize", "authorization"}, // the real thing
		{"authorizeTotpCode", "authorization"},
		{"authorize_signal", "authorization"},
		{"canAuthorizeRequest", "authorization"}, // buried, but at a hump
		{"deauthorize", ""},                      // the stated cost: mid-word, missed
	}
	for _, c := range cases {
		if got := m.ClassifyControl(c.name); got != c.want {
			t.Errorf("ClassifyControl(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

// Containment is only safe because the longest rule wins. Without that ordering
// `requireAuth` is a prefix of `requireAuthorization` and would misname it.
func TestClassifyControlPrefersTheLongerRule(t *testing.T) {
	m := Builtin()
	m.Controls = append(m.Controls,
		ControlRule{Name: "requireAuth", Kind: "authentication"},
		ControlRule{Name: "requireAuthorization", Kind: "authorization"},
	)
	if got := m.ClassifyControl("requireAuthorization"); got != "authorization" {
		t.Errorf("longer rule did not win: got %q", got)
	}
}
