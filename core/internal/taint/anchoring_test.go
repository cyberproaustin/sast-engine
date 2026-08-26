package taint_test

// WHERE a finding is, as opposed to whether it is one.
//
// Anchored means the engine tied this to the surface it enumerated (ADR-009), and it is
// what decides whether a finding fails a build. Several analyses assert it by
// construction, on the sound reasoning that a weak key in a file nothing routes to is
// still a weak key -- but "nothing routes to it" and "nothing can run it" are different
// facts, and the second one was never asked. An application had the `window.open` inside
// a settings button reported at error level, gating, on the strength of a handler local
// to the component; the component is not imported, re-exported or dynamically loaded
// anywhere in its own repository.
//
// None of this is expressible as a finding, which is exactly how it was wrong: the
// corpus score is identical either way, because every finding here is still reported.
//
// Regenerate the golden this reads with `make testdata`.

import (
	"testing"
)

func TestFindingsInUnreachedModulesAreNotAnchored(t *testing.T) {
	res := runScan(t, "unreferenced-component")

	// file:line -> whether the engine claims the enumerated surface reaches it.
	want := map[string]bool{
		// Imported by the process entry.
		"lib/preview.ts:8": true,
		// Imported by a page. Same call as the orphan; different answer.
		"ui/MountedPanel.tsx:5": true,
		// A page. Nothing imports it and nothing ever would -- the framework loads it by
		// PATH, and reading "no import" as "no caller" here would be a claim about the
		// framework rather than about the program.
		"pages/dashboard.tsx:8": true,
		// Nothing in the program names these two modules.
		"lib/legacy.ts:9":      false,
		"ui/OrphanPanel.tsx:8": false,
	}

	seen := map[string]bool{}
	for _, f := range res.Taint.Findings {
		key := f.SinkLoc.File + ":" + itoa(f.SinkLoc.Line)
		expected, ok := want[key]
		if !ok {
			t.Errorf("unexpected finding at %s (%s)", key, f.CWE)
			continue
		}
		seen[key] = true
		if f.EntryAnchored != expected {
			t.Errorf("%s: anchored %v, want %v", key, f.EntryAnchored, expected)
		}
		// The finding itself is never withdrawn. What is withdrawn is the claim about
		// where it is, and a build must not fail on a line nothing can reach.
		if got := res.Gates(f); got != expected {
			t.Errorf("%s: gates %v, want %v", key, got, expected)
		}
	}
	for key := range want {
		if !seen[key] {
			t.Errorf("no finding at %s at all -- the demotion must not remove one", key)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
