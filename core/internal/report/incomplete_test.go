package report

import (
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/surface"
)

// An INCOMPLETE line is an accusation against the enumeration, and an accusation nobody
// can check is one a reader learns to skip -- at which point it is worth less than
// nothing on the run where it is right. healthchecks reported 745 of 824 input-reading
// functions unreached over a surface an adjudicator had verified was complete, and the
// report said nothing at all about which functions or why.
func TestAnIncompleteSurfaceSaysWhichFunctionsAndWhy(t *testing.T) {
	b := &strings.Builder{}
	writeSurface(b, surface.Surface{
		Entries: make([]surface.EntryFacts, 4),
		Completeness: surface.Completeness{
			InputFunctions:              136,
			UnreachedInputFunctions:     134,
			NonProductionInputFunctions: 733,
			Unreached: []surface.UnreachedGroup{{
				Cause:           surface.CauseMissingCallEdge,
				Count:           75,
				FromReachedCode: 1,
				Modules:         []surface.ModuleCount{{Dir: "searx/engines", Count: 67}},
				Sample: []surface.UnreachedFunction{{
					Name:   "filter_request",
					Loc:    ir.Loc{File: "searx/botdetection/http_connection.py", Line: 27, Column: 1},
					Detail: "request.headers",
				}},
			}, {
				Cause:   surface.CauseNeverCalled,
				Count:   12,
				Modules: []surface.ModuleCount{{Dir: "searx/search", Count: 4}},
				Sample: []surface.UnreachedFunction{{
					Name: "dump_request",
					Loc:  ir.Loc{File: "searx/botdetection/_helpers.py", Line: 26, Column: 1},
				}},
			}},
		},
	})

	report := b.String()
	for _, want := range []string{
		"INCOMPLETE: 134 function(s)",
		"a further 733 read it in modules that cannot serve a request",
		"why the surface does not reach them:",
		"75  a call written with this name did not resolve to it",
		"1 of those from code the surface does reach",
		"searx/engines (67)",
		"filter_request at searx/botdetection/http_connection.py:27:1  [request.headers]",
		"12  nothing in the program calls them by name",
		"dump_request at searx/botdetection/_helpers.py:26:1",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report does not contain %q:\n%s", want, report)
		}
	}
}

// A surface the engine does not doubt says nothing, and must not start explaining a
// number it did not print.
func TestACompleteSurfaceExplainsNothing(t *testing.T) {
	b := &strings.Builder{}
	writeSurface(b, surface.Surface{
		Entries: make([]surface.EntryFacts, 40),
		Completeness: surface.Completeness{
			InputFunctions:              91,
			UnreachedInputFunctions:     12,
			NonProductionInputFunctions: 733,
			Unreached: []surface.UnreachedGroup{{
				Cause: surface.CauseNeverCalled, Count: 7,
				Modules: []surface.ModuleCount{{Dir: "hc/accounts", Count: 3}},
			}},
		},
	})
	if report := b.String(); strings.Contains(report, "why the surface does not reach them") ||
		strings.Contains(report, "a further 733") {
		t.Errorf("a surface the engine believes in explained itself anyway:\n%s", report)
	}
}
