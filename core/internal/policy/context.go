package policy

import "github.com/cyberproaustin/sast-engine/core/internal/ir"

// Context is the engine's own standing judgement about the CODE a finding names, as
// opposed to a declaration a team wrote about their application.
//
// It lives beside the declarations, and not inside a rule, because it is the same answer
// for every rule. Across twenty repositories, 12 of the 41 false positives attributed to
// the eight worst-scoring rules were one failure repeated: the rule found exactly the
// shape it was built to find, in a test fixture, in an example, or on a path only
// somebody who already holds the host can walk. All three CWE-321 firings were test keys
// -- one of them returned by a mocked readFileSync, one declared by a pytest fixture, one
// in a settings module that also selects test-only password hashing. Both CWE-336 firings
// were in one test_username.py whose own comment says the deterministic replay is
// intentional. CWE-295's was a Vitest case exercising the disabled-verification
// configuration; CWE-117's was inside a Playwright test; CWE-22's and CWE-918's were
// management commands opening the file and calling the server an operator named on their
// own command line. Written into eight rules, this check would have to be written again
// into the ninth.
//
// It is NOT a suppression and must not become one (ADR-013). A finding in one of these
// positions is still produced, still carries its whole evidence path, still prints in the
// text report, still travels in SARIF, and is still recorded by a baseline. The one thing
// that changes is which SET counts it: the engine ENUMERATES everything it found, and
// REPORTS the part of it that is a defect in the application somebody is being asked to
// defend. That is also why the answer is a sentence rather than a boolean -- a reader who
// is not shown a finding in the reported list is owed the reason it is not there.
//
// Nothing here reads a filename. Every term is a fact a frontend lowered — ir.Module
// .IsTest, ir.Module.Provenance, ir.EntryPoint.Trust — so a repository that spells its
// tests differently is answered by the frontend that knows that ecosystem's convention,
// which is the same division those three fields already draw.
type Context struct {
	// InTestModule is taint.Finding.InTestModule: the module ships with the repository
	// and does not run in production.
	InTestModule bool
	// Provenance is why the repository did not hand-write this module.
	Provenance ir.Provenance
	// Trust is who could cause the finding's value to enter the program — the SOURCE's
	// trust, not the sink's, so a scheduled job reading a column an HTTP request wrote
	// is remote and a management command reading its own argument is not. An unstated
	// trust reads as remote, because that is what every entry point was before there was
	// anything but a route.
	Trust ir.Trust
}

// NotReportedBecause returns why this context keeps a finding out of the reported set, or
// "" when the finding is reportable.
//
// The order is by how completely each answer disposes of the finding, which is also the
// order a reader wants: what the code IS settles more than who can reach it.
func (c Context) NotReportedBecause() string {
	switch {
	case c.InTestModule:
		// A key written into a test is in the repository and in its history exactly as
		// the rule says, and it is still not a production credential. It stays
		// enumerated for that reason: 34 of 59 hardcoded-secret findings in one batch
		// were test fixtures, and a real credential that someone parked in a fixture is
		// found by reading the enumerated set, never by promoting all 34 back into it.
		return "in a test module: it ships with the repository and does not run in production"
	case c.Provenance != "":
		// A weakness in a checked-in copy of somebody else's package is a true statement
		// and not a defect in this application. uptime-kuma measured the cost of ranking
		// the two together: protocol-compatibility DES in a vendored package sat beside
		// findings its maintainers could actually fix.
		return "in " + string(c.Provenance) + " code: the repository did not hand-write it"
	case c.Trust != "" && c.Trust != ir.Remote:
		// Reported as a defect, `error` and a build failure all say the same thing to
		// every consumer: a stranger can do this to you. A management command
		// interpolating an argument its operator typed, and a process reading the
		// environment it was started with, are reachable and are not that claim.
		return "reached only at " + string(c.Trust) +
			" trust: no lower-trust caller crosses a boundary into it"
	}
	return ""
}

// Reportable reports whether a finding in this context belongs in the set handed to a
// maintainer as a defect in their application.
func (c Context) Reportable() bool { return c.NotReportedBecause() == "" }
