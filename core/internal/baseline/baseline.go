// Package baseline records findings a team has already seen, so that a run can fail on
// what is new without failing on what was already there.
//
// This is what lets the engine be adopted on an existing codebase. A tool that reports a
// repository's entire history on the first run gets switched off before anyone reads the
// second finding, and the honest answer is not to report less — it is to say which
// findings are new.
//
// A baseline is NOT a suppression list and shares nothing with ADR-013's reasoning about
// declared policy. It makes no claim that anything is acceptable; it records only that a
// finding was present at a moment in time. Every baselined finding is still reported,
// still counted, and still says that it is baselined.
package baseline

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

// Format is the on-disk version of a baseline file.
const Format = "sast-baseline/v1"

// Entry is one recorded finding. The fields beyond the fingerprint are for a human
// reading the file in review; nothing matches on them.
type Entry struct {
	Fingerprint string `json:"fingerprint"`
	CWE         string `json:"cwe"`
	Policy      string `json:"policy"`
	EntryPoint  string `json:"entryPoint,omitempty"`
	Sink        string `json:"sink,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Baseline is a set of known findings.
type Baseline struct {
	Format  string  `json:"format"`
	Entries []Entry `json:"entries"`

	known map[string]bool
}

// Known reports whether this fingerprint was in the baseline.
func (b *Baseline) Known(fingerprint string) bool {
	if b == nil {
		return false
	}
	return b.known[fingerprint]
}

// Count is how many findings the baseline records.
func (b *Baseline) Count() int {
	if b == nil {
		return 0
	}
	return len(b.Entries)
}

// Load reads a baseline. A nil result with no error means none was supplied, which is
// distinct from an empty one: an empty baseline asserts that the codebase was clean when
// it was written.
func Load(path string) (*Baseline, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open baseline: %w", err)
	}
	defer f.Close()
	return Read(f)
}

// Read parses a baseline document.
func Read(r io.Reader) (*Baseline, error) {
	var b Baseline
	dec := json.NewDecoder(r)
	// An unknown key is a typo or a newer format, and either way the baseline would
	// silently match nothing — which reads exactly like a clean run.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("decode baseline: %w", err)
	}
	if b.Format != Format {
		return nil, fmt.Errorf("baseline format %q is not %q", b.Format, Format)
	}
	b.known = make(map[string]bool, len(b.Entries))
	for _, e := range b.Entries {
		if e.Fingerprint == "" {
			return nil, fmt.Errorf("baseline entry has no fingerprint")
		}
		b.known[e.Fingerprint] = true
	}
	return &b, nil
}

// Write emits a baseline, sorted so that regenerating it produces a reviewable diff
// rather than a reordered file.
func Write(w io.Writer, entries []Entry) error {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Fingerprint < entries[j].Fingerprint })
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Baseline{Format: Format, Entries: entries})
}
