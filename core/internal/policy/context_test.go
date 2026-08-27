package policy_test

import (
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/policy"
)

// The engine publishes two sets, and this is the only thing that decides which one a
// finding is in. Every case here is a finding an adjudicator ruled on: 12 of the 41 false
// positives from one batch's worst-scoring rules were a correct rule firing in one of
// these three positions.
func TestContextDecidesWhichSetAFindingIsIn(t *testing.T) {
	for _, c := range []struct {
		name     string
		ctx      policy.Context
		reported bool
		says     string
	}{
		{"application code reached by a stranger",
			policy.Context{Trust: ir.Remote}, true, ""},

		{"an unstated trust is remote",
			policy.Context{}, true, ""},

		// medplum's profile-auth.test.ts, saleor's conftest.py and its tests/settings.py
		// were all CWE-321, and all three were keys a test declares for itself.
		{"a key declared by a test fixture",
			policy.Context{InTestModule: true, Trust: ir.Remote}, false, "test module"},

		{"a weakness in a checked-in copy of somebody else's package",
			policy.Context{Provenance: ir.Vendored, Trust: ir.Remote}, false, "vendored"},

		// linkding's import_netscape opens the path its operator typed, and wger's
		// min_server_version calls the server its operator named.
		{"a management command reading its own argument",
			policy.Context{Trust: ir.Operator}, false, "operator"},

		{"a timer firing code nothing outside the process reaches",
			policy.Context{Trust: ir.Internal}, false, "internal"},

		// The strongest reason is the one worth publishing: a reader told "in a test
		// module" learns more than one told "at operator trust" about the same line.
		{"a test fixture in a management command",
			policy.Context{InTestModule: true, Trust: ir.Operator}, false, "test module"},
	} {
		why := c.ctx.NotReportedBecause()
		if got := c.ctx.Reportable(); got != c.reported {
			t.Errorf("%s: reportable=%v, want %v (%q)", c.name, got, c.reported, why)
		}
		if c.reported && why != "" {
			t.Errorf("%s: a reported finding must carry no reason, got %q", c.name, why)
		}
		if !c.reported && !strings.Contains(why, c.says) {
			t.Errorf("%s: reason %q does not say %q", c.name, why, c.says)
		}
	}
}

// A finding that is not in the list a reader is looking at is owed the reason it is
// elsewhere. Every consumer prints this sentence, so an empty one would be a blank line
// where an explanation belongs.
func TestEveryUnreportedContextStatesItsReason(t *testing.T) {
	for _, ctx := range []policy.Context{
		{InTestModule: true},
		{Provenance: ir.Example},
		{Provenance: ir.Generated},
		{Provenance: ir.Tooling},
		{Trust: ir.Operator},
		{Trust: ir.Internal},
	} {
		if why := ctx.NotReportedBecause(); why == "" {
			t.Errorf("%+v is not reported and says nothing about why", ctx)
		}
	}
}
