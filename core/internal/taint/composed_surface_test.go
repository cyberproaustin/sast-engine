package taint_test

// Two registration idioms that produce no call this engine can match, and therefore
// produced no entry points at all. Both are asserted exactly and in BOTH directions:
// what must appear, and what must not. ADR-009 makes the enumeration the thing every
// finding rests on, so a model that is slightly too generous does not merely add a row --
// it puts an address on the surface that answers nothing, and every count downstream is
// then a lie.

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

// A tRPC procedure's address is not written anywhere.
//
// It is the key the procedure is filed under, joined to the keys of every router that
// object is nested inside -- and those keys are in files that never mention each other's
// contents. `report.export` here comes from `app.ts` (`report:`) and `reports.ts`
// (`export:`), and the procedure itself is declared in a third place and exported by name.
//
// Measured on documenso: 62 entry points over 274 procedures, with the scan's own
// completeness banner reporting 76 functions that read caller input which no entry point
// could reach. With the idiom modelled it lowers to 355 and the banner is gone.
func TestTrpcProceduresAreEnumeratedWithTheirComposedAddress(t *testing.T) {
	res := runScan(t, "trpc-router")

	// The address a caller writes, the verb the transport uses, and the CONTROL -- which
	// in a tRPC codebase is the builder the chain started from and nothing else.
	want := map[string]string{
		// `.meta({ openapi: { method, path } })` IS the REST address; the dotted
		// procedure name is kept beside it rather than instead of it.
		"POST /report/export": "authenticatedProcedure",
		// No metadata: the address is the composed procedure name, and the verb comes
		// from the terminal -- a query is a GET and a mutation is a POST.
		"GET report.list":   "authenticatedProcedure",
		"GET report.status": "procedure",
		// Composed through a router declared inline in the root.
		"POST admin.purge": "authenticatedProcedure",
	}

	got := map[string]string{}
	for _, e := range res.Surface.Entries {
		if e.EntryPoint.Framework != "trpc" {
			continue
		}
		control := ""
		for _, c := range e.Controls {
			if c.Scope == "route" {
				control = c.Name
			}
		}
		got[e.Label()] = control
		// A procedure answers whoever can reach the server. Nothing about a builder
		// chain says otherwise, and an entry point that claimed less would rank every
		// finding under it as something only an operator can cause.
		if e.TrustLevel() != ir.Remote {
			t.Errorf("%s is trusted %q, want remote", e.Label(), e.TrustLevel())
		}
	}

	for label, control := range want {
		if _, ok := got[label]; !ok {
			t.Errorf("missing entry point %s", label)
			continue
		}
		if got[label] != control {
			t.Errorf("%s carries control %q, want %q", label, got[label], control)
		}
	}
	for label := range got {
		if _, ok := want[label]; !ok {
			t.Errorf("%s was enumerated and is not a procedure", label)
		}
	}

	// The terminal name is shared with every cache and query client in the ecosystem.
	// `queryClient.mutation(fn)` in this corpus has the same four tokens as a procedure
	// and is not one; what separates them is the builder in front of it.
	for _, e := range res.Surface.Entries {
		if e.EntryPoint.Detail["mount"] == "queryClient" {
			t.Errorf("a query client's mutation was enumerated as a route: %s", e.Label())
		}
	}
}

// A Graphene schema registers its operations as CLASS ATTRIBUTES.
//
// There is no call to match anywhere: the URLconf carries one view, and behind it sit the
// operations, each a `SomeMutation.Field()` assignment in a class body. saleor lowered to
// 29 entry points with its entire GraphQL API counted as one of them; with the schema read
// it lowers to 447, and the 418 operations match its own checked-in `schema.graphql` field
// for field -- 2 queries and 2 mutations missing, both federation internals the source
// never spells, and nothing invented.
func TestGrapheneOperationsAreEnumeratedFromTheSchemaRoots(t *testing.T) {
	res := runScan(t, "graphene-schema")

	// The camel spelling, because that is the name the schema publishes: Graphene renames
	// every field by default, and `export_report` answers nothing.
	// The control's identity is the DECLARATION and not the permission it names, because
	// which permission of a domain an operation needs is a design decision about the
	// object: keying on the permission reported eight false advisories over saleor, among
	// them `customerCreate` for not applying `AccountPermissions.MANAGE_STAFF` while
	// declaring `AccountPermissions.MANAGE_USERS`. What a reader is SHOWN is still the
	// permission as written.
	want := map[string]string{
		"MUTATION exportReport":   "Meta.permissions=ReportPermissions.MANAGE_REPORTS",
		"MUTATION rebuildReports": "Meta.permissions=ReportPermissions.MANAGE_REPORTS",
		"MUTATION archiveReport":  "",
		"QUERY report":            "",
	}

	got := map[string]string{}
	for _, e := range res.Surface.Entries {
		if e.EntryPoint.Framework != "graphene" {
			continue
		}
		control := ""
		for _, c := range e.Controls {
			if c.Scope == "route" {
				control = c.Name
			}
		}
		got[e.Label()] = control
		if e.TrustLevel() != ir.Remote {
			t.Errorf("%s is trusted %q, want remote", e.Label(), e.TrustLevel())
		}
		// Not an HTTP address, and deliberately not spelled as one: every operation here
		// answers at the single URL the URLconf registers, so printing a path per
		// operation would tell an operator the application serves that many addresses.
		if e.EntryPoint.Kind != "graphql-operation" {
			t.Errorf("%s has kind %q", e.Label(), e.EntryPoint.Kind)
		}
	}

	for label, control := range want {
		if _, ok := got[label]; !ok {
			t.Errorf("missing operation %s", label)
			continue
		}
		if got[label] != control {
			t.Errorf("%s carries control %q, want %q", label, got[label], control)
		}
	}
	for label := range got {
		if _, ok := want[label]; !ok {
			t.Errorf("%s was enumerated and is not an operation", label)
		}
	}

	// The failure this pass exists to avoid, said as a property. Every mutation PAYLOAD in
	// a Graphene application is a `graphene.ObjectType` whose fields are declared exactly
	// as a root's are, so the shape cannot tell a result from an operation. What can is
	// that somebody handed the class to `graphene.Schema`: reading the shape alone turned
	// saleor's 418 operations into 538, and 120 of the extra were payload fields.
	for _, e := range res.Surface.Entries {
		if e.EntryPoint.Detail["mount"] == "ReportType" {
			t.Errorf("a payload field was enumerated as an operation: %s", e.Label())
		}
	}
}
