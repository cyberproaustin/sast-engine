package report

import (
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/surface"
)

// An example route is useful inventory and zero application routes is still zero.
// jupyterhub's report failed precisely because the first fact overwrote the second.
func TestExampleEntriesDoNotPopulateTheApplicationSurfaceSummary(t *testing.T) {
	b := &strings.Builder{}
	writeSurface(b, surface.Surface{
		NonApplicationEntries: []surface.EntryFacts{{
			EntryPoint: ir.EntryPoint{
				Kind:   "http-route",
				Detail: map[string]string{"method": "GET", "path": "/demo"},
				Loc:    ir.Loc{File: "examples/demo.py", Line: 15},
			},
			Provenance: ir.Example,
			Method:     "GET",
			Path:       "/demo",
		}},
		Completeness: surface.Completeness{InputFunctions: 1, UnreachedInputFunctions: 1},
	})

	report := b.String()
	for _, want := range []string{
		"surface: 0 entry point(s)",
		"INCOMPLETE: none enumerated",
		"non-application surface: 1 entry point(s)",
		"example: 1",
		"GET /demo",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("surface report does not contain %q:\n%s", want, report)
		}
	}
}
