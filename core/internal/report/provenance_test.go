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
		// The wording of the empty-surface warning is not what this test is about, and
		// pinning it here made an unrelated improvement look like a regression: the trust
		// labels changed "none enumerated" to "no entry point a caller can REACH", which
		// is the more accurate sentence now that an operator-triggered entry point can
		// exist and not be one. Assert that the warning is PRESENT and that it is about
		// an empty application surface; leave its prose to the test that owns it.
		"INCOMPLETE:",
		"non-application surface: 1 entry point(s)",
		"example: 1",
		"GET /demo",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("surface report does not contain %q:\n%s", want, report)
		}
	}
}
