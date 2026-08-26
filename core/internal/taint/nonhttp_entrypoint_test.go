package taint_test

// The surface stopped being all HTTP routes, and what each new class SAYS about itself is
// not expressible as a finding.
//
// A scheduled job reported as a route would be a false statement about who can reach the
// code, and the corpus scores cannot catch it: they score findings, and the trust label is
// the part of an entry point that never becomes one. So it is asserted here, entry point
// by entry point, in the same spirit as the route-metadata assertions next door.
//
// Regenerate the goldens these read with `make testdata`.

import (
	"sort"
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

// classLabels renders one line per entry point: kind, trust, and whatever detail names
// this particular registration.
func classLabels(doc *ir.IR) []string {
	out := make([]string, 0, len(doc.EntryPoints))
	for _, ep := range doc.EntryPoints {
		name := ""
		for _, key := range []string{"command", "event", "schedule", "trigger", "start", "path"} {
			if v := ep.Detail[key]; v != "" {
				name = v
				break
			}
		}
		out = append(out, strings.Join([]string{ep.Kind, string(ep.TrustLevel()), name}, " "))
	}
	sort.Strings(out)
	return out
}

func assertClasses(t *testing.T, corpus string, want []string) {
	t.Helper()
	got := classLabels(loadCorpusIR(t, corpus))
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("%s: want %d entry points, got %d:\n  %s", corpus, len(want), len(got),
			strings.Join(got, "\n  "))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s: entry point %d\n  want %q\n  got  %q", corpus, i, want[i], got[i])
		}
	}
}

// A timer and a bus are entry points; a one-shot delay, a socket and a calendar are not.
//
// The three silences are the whole cost of the class and each is a different reason. A
// `setTimeout` is how every debounce in JavaScript is written. A `socket.on` is the same
// three letters as `bus.on` and answers a REMOTE caller, so labelling it internal would
// understate it as badly as ignoring the bus overstates the rest — the receiver's type
// decides it, and nothing is claimed where the checker cannot say. And `planner.schedule`
// is handed two dates and no function: a bare method name is not an identity.
func TestBackgroundEntryPointClasses(t *testing.T) {
	assertClasses(t, "scheduled-jobs", []string{
		"http-route remote /jobs",
		"http-route remote /webhooks",
		// A cron expression, an interval, a bound method reference, and a callback read
		// off a property of a job table. Four spellings of one registration.
		"scheduled-job internal 0 3 * * *",
		"scheduled-job internal 60000",
		"scheduled-job internal 3600000 sweep",
		"scheduled-job internal Cron",
		"event-consumer internal job-finished",
		// A dev-watch script. Enumerated -- it is a real recurring callback -- and kept
		// out of the APPLICATION's surface by its provenance, which the next test asserts.
		"scheduled-job internal 1000",
	})
}

// A management command names itself, and says which arguments it declared.
//
// The class is decided by the BASE CLASS. `Maintenance` has a `handle` method and derives
// from nothing, so no operator runs it and it is not here; keying on the
// `management/commands/` directory instead would have enumerated an `__init__.py` and
// missed a command a project keeps somewhere else.
func TestManagementCommandClasses(t *testing.T) {
	assertClasses(t, "management-command", []string{
		"cli-command operator commands",
		"cli-command operator commands",
		"cli-command operator commands",
	})
}

// A program start is where the LANGUAGE says a process begins, and nowhere else.
//
// `tools.py` does work at its top level exactly as every module does, and it is not an
// entry point: module-level initialization taken as a class on its own would make one of
// every settings file in a tree, and a surface nobody can audit is worse than no surface.
func TestProcessStartClasses(t *testing.T) {
	assertClasses(t, "process-start", []string{
		"process-start operator __main__ guard",
		// A release script under `devscripts/`. A real program start, and not the
		// application's; the next test asserts which side of the surface it lands on.
		"process-start operator __main__ guard",
	})
}

// Build and development machinery is enumerated and kept out of the application's count.
//
// The surface is the primary output and an operator audits it against the application
// they run (ADR-009). A `setInterval` in a dev-watch script and a `__main__` guard in a
// release script are both real, and neither is something the deployed application does --
// the same category error an example route is, answered the same way.
func TestToolingEntriesAreNotApplicationSurface(t *testing.T) {
	for _, c := range []struct {
		corpus string
		app    int
		tool   int
	}{
		{"scheduled-jobs", 7, 1},
		{"process-start", 1, 1},
	} {
		res := runScan(t, c.corpus)
		if len(res.Surface.Entries) != c.app {
			t.Errorf("%s: want %d application entry points, got %d",
				c.corpus, c.app, len(res.Surface.Entries))
		}
		tooling := 0
		for _, e := range res.Surface.NonApplicationEntries {
			if e.Provenance == ir.Tooling {
				tooling++
			}
		}
		if tooling != c.tool {
			t.Errorf("%s: want %d tooling entry points held outside the application count, got %d",
				c.corpus, c.tool, tooling)
		}
	}
}

// A callback that cannot be resolved is not an entry point.
//
// The two shapes this rejects are both in the corpus and both were measured on production
// code: a forwarding helper registering its own parameter, and an application method
// spelled `schedule` that takes a record. A background job has no address the way a route
// does -- it IS its callback -- so a row naming no function contributes no reachability
// and cannot be reasoned about.
func TestEveryBackgroundEntryNamesAFunction(t *testing.T) {
	for _, corpus := range []string{"scheduled-jobs", "process-start", "management-command"} {
		for _, ep := range loadCorpusIR(t, corpus).EntryPoints {
			if ep.TrustLevel() != ir.Remote && ep.FunctionID == "" {
				t.Errorf("%s: %s entry point at %s names no function", corpus, ep.Kind, ep.Loc)
			}
		}
	}
}

// Trust is stated by the frontend and read as remote when it is absent.
//
// The default is the conservative one on purpose: every entry point in this engine was a
// route before there was anything else, and a frontend that goes quiet must not make the
// core quieter with it (ADR-003).
func TestUnstatedTrustIsRemote(t *testing.T) {
	if (ir.EntryPoint{}).TrustLevel() != ir.Remote {
		t.Errorf("an entry point that says nothing about trust must be read as remote")
	}
	if (ir.EntryPoint{Trust: ir.Internal}).TrustLevel() != ir.Internal {
		t.Errorf("a stated trust must be kept")
	}
}

// A finding that only an operator or a timer can reach is reported and does not gate.
//
// SARIF's `error` and this engine's gate both mean "a caller can do this to you", and a
// management command's own argument is not that claim. It is not nothing either, which is
// why it stays in the output at warning rather than being dropped.
func TestOperatorReachableFindingsDoNotGate(t *testing.T) {
	res := runScan(t, "management-command")
	if len(res.Taint.Findings) == 0 {
		t.Fatal("expected the command corpus to report its command injections")
	}
	for _, f := range res.Taint.Findings {
		if f.SourceTrust() != ir.Operator {
			t.Errorf("%s at %s: want operator trust, got %q", f.CWE, f.SinkLoc, f.SourceTrust())
		}
		if f.Actionable() {
			t.Errorf("%s at %s gates, and only an operator can reach it", f.CWE, f.SinkLoc)
		}
	}
}

// A scheduled job reading what a REQUEST stored carries the request's trust.
//
// The alternative reading — trust from the entry point holding the sink — would call this
// internal and rank it below a first-order finding on the same data, which is the mistake
// that makes second-order analysis worthless: the whole point of it is that the caller is
// still the caller after the request has ended.
func TestStoredValueKeepsTheWritersTrust(t *testing.T) {
	res := runScan(t, "scheduled-jobs")
	anchored := 0
	for _, f := range res.Taint.Findings {
		if !f.EntryAnchored {
			continue
		}
		anchored++
		if f.SourceTrust() != ir.Remote {
			t.Errorf("%s at %s: a column an HTTP request wrote must stay remote, got %q",
				f.CWE, f.SinkLoc, f.SourceTrust())
		}
	}
	if anchored != 3 {
		t.Errorf("want 3 findings anchored to background entry points, got %d", anchored)
	}
}
