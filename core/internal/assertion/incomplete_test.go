package assertion

import (
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/scan"
	"github.com/cyberproaustin/sast-engine/core/internal/surface"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// A requirement may only be reported satisfied over a surface the engine believes in.
//
// The empty case was always handled. The incomplete case was not, and it is the more
// dangerous of the two because it does not look like blindness: jupyterhub printed
// "0 violated, 6 satisfied" having enumerated nine entry points, every one of them from its
// examples directory and none of the sixty-two real ones. A false positive costs somebody
// an afternoon. This tells them their application is fine.
func TestNothingIsSatisfiedOverASurfaceTheEngineDoubts(t *testing.T) {
	req := Requirement{ID: "V5.3.4", CWEs: []string{"CWE-89"}, AssertedBy: []string{"taint"}}
	ran := scan.Result{Taint: taint.Result{Applicable: true}}

	entries := func(n int) []surface.EntryFacts { return make([]surface.EntryFacts, n) }

	for _, c := range []struct {
		name    string
		res     scan.Result
		want    State
		wantWhy string
	}{
		{
			name: "a surface that accounts for the program",
			res: func() scan.Result {
				r := ran
				r.Surface = surface.Surface{Entries: entries(40),
					Completeness: surface.Completeness{InputFunctions: 50, UnreachedInputFunctions: 3}}
				return r
			}(),
			want: Satisfied,
		},
		{
			name: "jupyterhub: nine entry points, sixty-two routes, hundreds unreached",
			res: func() scan.Result {
				r := ran
				r.Surface = surface.Surface{Entries: entries(9),
					Completeness: surface.Completeness{InputFunctions: 400, UnreachedInputFunctions: 391}}
				return r
			}(),
			want:    NotEvaluated,
			wantWhy: "incomplete",
		},
		{
			name: "no surface at all",
			res: func() scan.Result {
				r := ran
				r.Surface = surface.Surface{Completeness: surface.Completeness{InputFunctions: 821}}
				return r
			}(),
			want:    NotEvaluated,
			wantWhy: "no entry points",
		},
	} {
		got := evaluateOne(req, c.res, map[string]int{}, map[string][]string{})
		if got.State != c.want {
			t.Errorf("%s: state %q, want %q", c.name, got.State, c.want)
		}
		if c.wantWhy != "" && !strings.Contains(got.Reason, c.wantWhy) {
			t.Errorf("%s: reason %q does not say why (want %q)", c.name, got.Reason, c.wantWhy)
		}
	}

	// A violation still counts. An incomplete surface casts doubt on silence, never on
	// something the engine actually found.
	r := ran
	r.Surface = surface.Surface{Entries: entries(9),
		Completeness: surface.Completeness{InputFunctions: 400, UnreachedInputFunctions: 391}}
	if got := evaluateOne(req, r, map[string]int{"CWE-89": 2}, map[string][]string{}); got.State != Violated {
		t.Errorf("a finding over an incomplete surface is still a violation, got %q", got.State)
	}
}
