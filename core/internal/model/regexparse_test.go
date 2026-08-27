package model

import "testing"

func TestAnchoredRegexExcludesPathSyntax(t *testing.T) {
	for _, pattern := range []string{
		`/^[0-9a-f-]+\.png$/`,
		`^[0-9a-f-]+\.(?:png|svg)$`,
	} {
		if !AnchoredRegexExcludes(pattern, "/", `\`, "..") {
			t.Errorf("%s should prove that neither a separator nor a double dot can occur", pattern)
		}
	}
}

func TestAnchoredRegexRefusesAnUnprovedPathLanguage(t *testing.T) {
	for _, pattern := range []string{
		`/[0-9a-f-]+\.png/`,    // a safe substring says nothing about the whole value
		`/^safe$|[a-z/]+/`,     // anchors do not govern every alternative
		`/^[a-z/]+\.png$/`,     // slash is admitted
		`/^[a-z.]+\.png$/`,     // a repeated class can make `..`
		`/^[a-z]+\.{2}png$/`,   // so can a fixed count
		`/^([a-z]+)\1\.png$/`,  // a backreference is outside the proved language
		`/^[0-9a-f-]+\.png$/g`, // stateful/flagged regexes are deliberately unproved
	} {
		if AnchoredRegexExcludes(pattern, "/", `\`, "..") {
			t.Errorf("%s must not be credited as a path sanitizer", pattern)
		}
	}
}

func TestDollarDoesNotProveAHeaderHasNoNewline(t *testing.T) {
	// In JavaScript `$` may match before a final line terminator, so this accepts
	// "safe\n" even though the repeated class itself does not contain a newline.
	if AnchoredRegexExcludes(`/^[a-z]+$/`, "\r", "\n") {
		t.Error("a dollar anchor alone must not clear a header or log-line sink")
	}
	if !AnchoredRegexExcludes(`/^[a-z0-9 -]+$/`, "<", ">", "&", `"`) {
		t.Error("the same final newline does not create markup syntax")
	}
}
