package model

import "testing"

// The whole difference between two weaknesses written with the same three lines.
//
// A record selected by a value the caller sent is authentication when the caller had to
// POSSESS the value and an insecure direct object reference when they could have counted
// their way to it, and the only thing that separates them is the name the program gave
// the field. These are the names that decide it, including the ones that carry a
// credential word and name a row anyway.
func TestNamesSecretFieldSeparatesASecretFromAnIdentifier(t *testing.T) {
	m := Builtin()
	cases := []struct {
		leaf string
		want bool
		why  string
	}{
		{"token", true, "documenso's signing links, all five of them"},
		{"directTemplateToken", true, "a compound naming the same thing"},
		{"access_token", true, "separators are folded before matching"},
		{"password", true, ""},
		{"apiKey", true, ""},
		{"authorization", true, "the header a bearer credential travels in"},

		{"documentId", false, "an identifier, and the shape this must not silence"},
		{"fieldId", false, ""},
		{"slug", false, ""},
		{"email", false, "an identifier a caller can guess, however private it feels"},

		{"tokenId", false, "a credential word naming a primary key is a primary key"},
		{"apiKeyId", false, ""},
		{"secret_id", false, ""},
		{"tokenIds", false, "the plural of a primary key is still primary keys"},

		{"csrfToken", false, "a credential nobody hides: the page echoes it back"},
		{"xsrf_token", false, ""},
	}
	for _, c := range cases {
		if got := m.NamesSecretField(c.leaf); got != c.want {
			t.Errorf("NamesSecretField(%q) = %v, want %v (%s)", c.leaf, got, c.want, c.why)
		}
	}
}
