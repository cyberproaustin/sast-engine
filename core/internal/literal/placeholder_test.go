package literal

import "testing"

// Test modules produced 34 of 59 hardcoded-secret findings across ten repositories, and an
// independent reader judged every one of them false. Suppressing test files wholesale would
// have thrown away the case that matters most, so the bar rises there instead of closing:
// a value must not look like a placeholder.
func TestPlaceholdersInTestsAreNotLeaks(t *testing.T) {
	placeholders := []string{
		// Every false hardcoded-credential finding the corpus produced in a test file.
		`http://user:pass@example.org:80`,
		`http://user:pass@example.dummytld:80`,
		`http://user:pass@example:80`,
		`not hex`,
		`abc123`,
		`test_password`,
		`route-send-test-secret`,
		// The shapes those generalise to.
		`postgres://admin:password@localhost:5432/db`,
		`changeme`,
		`my-dummy-key`,
	}
	for _, p := range placeholders {
		if !IsPlaceholder(p) {
			t.Errorf("%q is somebody making a test pass, not a credential", p)
		}
	}

	// The case the whole design exists to keep. A real key committed to a test is in the
	// repository and in its history, and that is exactly how credentials leak.
	real := []string{
		`sk_live_51H8xQ2eZvKYlo2CkqPZmNvBnQ7RtYuIoPaSdFgHjKlZxCvBnM`,
		`AKIAIOSFODNN7EXAMPLE`, // the prefix wins; length and the word both say otherwise
		`ghp_16C7e42F292c6912E7710c838347Ae178B4a`,
		`xoxb-2401-2401-e7dJ0aRPXuNvVmZaKfLwQpTs`,
		`-----BEGIN RSA PRIVATE KEY-----`,
		`9f8c2b7e4a1d6350fbc9e28d75a4103ef6b28c91`, // a long digest with nothing to say
	}
	for _, r := range real {
		if IsPlaceholder(r) {
			t.Errorf("%q is the finding this rule exists to preserve", r)
		}
	}
}
