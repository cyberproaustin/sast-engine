// Package bench scores analysis output against a corpus's declared expectations.
//
// It exists so that "more precise" is a measurement rather than a claim. Recall is
// the easy half; the half that matters is the false-positive rate on code that is
// safe, which is why a corpus expecting zero findings is a first-class case here.
package bench

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// Expectation is one finding a corpus asserts should be produced.
type Expectation struct {
	CWE         string `json:"cwe"`
	SinkFile    string `json:"sinkFile"`
	SinkLine    int    `json:"sinkLine"`
	SourceLabel string `json:"sourceLabel"`
	Confidence  string `json:"confidence,omitempty"`
	Note        string `json:"note,omitempty"`
}

func (e Expectation) String() string {
	return fmt.Sprintf("%s at %s:%d from %s", e.CWE, e.SinkFile, e.SinkLine, e.SourceLabel)
}

// Corpus is a scored fixture: sources plus what they are asserted to contain.
type Corpus struct {
	Name        string        `json:"corpus"`
	Description string        `json:"description"`
	Expected    []Expectation `json:"expected"`
}

// Report is the outcome of scoring one corpus.
type Report struct {
	Corpus          string
	NotApplicable   bool
	TruePositives   int
	FalsePositives  []taint.Finding
	FalseNegatives  []Expectation
	WrongConfidence []Mismatch
}

// Mismatch is a finding that was expected and found, but tiered differently than
// the corpus asserts. Confidence drives the gate, so drift here is a real defect.
type Mismatch struct {
	Expectation Expectation
	Got         taint.Confidence
}

// Precision is TP / (TP + FP). A run that claims nothing cannot be wrong, so an
// empty claim set scores 1.
func (r Report) Precision() float64 {
	claimed := r.TruePositives + len(r.FalsePositives)
	if claimed == 0 {
		return 1
	}
	return float64(r.TruePositives) / float64(claimed)
}

// Recall is TP / (TP + FN). A corpus asserting nothing cannot be missed.
func (r Report) Recall() float64 {
	expected := r.TruePositives + len(r.FalseNegatives)
	if expected == 0 {
		return 1
	}
	return float64(r.TruePositives) / float64(expected)
}

func (r Report) Clean() bool {
	return len(r.FalsePositives) == 0 && len(r.FalseNegatives) == 0 && len(r.WrongConfidence) == 0
}

// Summary is a one-line result suitable for CI output.
func (r Report) Summary() string {
	if r.NotApplicable {
		return fmt.Sprintf("%-28s NOT APPLICABLE (analysis did not run)", r.Corpus)
	}
	return fmt.Sprintf(
		"%-28s precision %.2f  recall %.2f   tp=%d fp=%d fn=%d",
		r.Corpus, r.Precision(), r.Recall(), r.TruePositives, len(r.FalsePositives), len(r.FalseNegatives),
	)
}

// LoadCorpus reads a corpus expectation manifest.
func LoadCorpus(path string) (Corpus, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Corpus{}, fmt.Errorf("read corpus manifest: %w", err)
	}
	var c Corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		return Corpus{}, fmt.Errorf("parse corpus manifest %s: %w", path, err)
	}
	return c, nil
}

// Score matches findings against expectations. A finding matches an expectation
// when the vulnerability class, the sink position, and the originating source all
// agree — matching on the sink alone would let a finding with the wrong provenance
// count as correct.
func Score(c Corpus, res taint.Result) Report {
	rep := Report{Corpus: c.Name, NotApplicable: !res.Applicable}
	if !res.Applicable {
		// An analysis that did not run is not a clean scan (ADR-003), so every
		// expectation counts as missed rather than silently passing.
		rep.FalseNegatives = append(rep.FalseNegatives, c.Expected...)
		return rep
	}

	claimed := make([]bool, len(res.Findings))

	for _, want := range c.Expected {
		matched := -1
		for i, got := range res.Findings {
			if claimed[i] {
				continue
			}
			if matches(want, got) {
				matched = i
				break
			}
		}
		if matched < 0 {
			rep.FalseNegatives = append(rep.FalseNegatives, want)
			continue
		}
		claimed[matched] = true
		rep.TruePositives++
		if want.Confidence != "" && string(res.Findings[matched].Confidence) != want.Confidence {
			rep.WrongConfidence = append(rep.WrongConfidence, Mismatch{
				Expectation: want,
				Got:         res.Findings[matched].Confidence,
			})
		}
	}

	for i, got := range res.Findings {
		if !claimed[i] {
			rep.FalsePositives = append(rep.FalsePositives, got)
		}
	}
	return rep
}

func matches(want Expectation, got taint.Finding) bool {
	return want.CWE == got.CWE &&
		want.SinkFile == got.SinkLoc.File &&
		want.SinkLine == got.SinkLoc.Line &&
		want.SourceLabel == got.SourceLabel
}
