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
