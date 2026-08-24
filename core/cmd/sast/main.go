// Command sast runs the core analysis over a lowered program (Program IR).
//
// It never parses source. A language frontend produces IR; this consumes it.
//
// Exit codes:
//
//	0  analysis ran, no gating findings
//	1  analysis ran, gating findings present
//	2  error
//	3  analysis NOT APPLICABLE — it did not run, and this is not a clean result
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/baseline"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/policy"
	"github.com/cyberproaustin/sast-engine/core/internal/report"
	"github.com/cyberproaustin/sast-engine/core/internal/scan"
)

const version = "0.1.0"

const (
	exitClean         = 0
	exitGating        = 1
	exitError         = 2
	exitNotApplicable = 3
)

func main() {
	os.Exit(run())
}

func run() int {
	// `sast scan <dir>` lowers and analyzes in one step. `sast -ir <file>` consumes a
	// Program IR someone else produced, which is what the tests and any pipeline that
	// wants to lower once and analyze repeatedly use.
	scanDir, lang := "", ""
	if len(os.Args) > 1 && os.Args[1] == "scan" {
		if len(os.Args) < 3 || strings.HasPrefix(os.Args[2], "-") {
			fmt.Fprintf(os.Stderr, "usage: sast scan <directory> [flags]\n")
			return exitError
		}
		scanDir = os.Args[2]
		os.Args = append(os.Args[:1], os.Args[3:]...)
	}
	langFlag := flag.String("lang", "", "force a frontend (typescript | python) instead of choosing by file count")

	irPath := flag.String("ir", "-", "path to a Program IR document, or - for stdin")
	format := flag.String("format", "text", "output format: text | sarif")
	failOn := flag.String("fail-on", "gating", "what fails the run: gating | any | never")
	policyPath := flag.String("policy", "", "path to a declared policy document (see ADR-011/013)")
	baselinePath := flag.String("baseline", "", "path to a baseline of already-known findings; recorded findings are reported but do not gate")
	writeBaseline := flag.String("write-baseline", "", "record this run's findings to a baseline file and exit 0")
	changedPath := flag.String("changed", "", "path to a file of changed paths, one per line (`git diff --name-only`); only findings touching them can gate")
	flag.Parse()
	lang = *langFlag

	if scanDir != "" {
		home, err := findHome()
		if err != nil {
			fmt.Fprintf(os.Stderr, "sast: %v\n", err)
			return exitError
		}
		lowered, err := lower(home, scanDir, lang)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sast: %v\n", err)
			return exitError
		}
		defer os.Remove(lowered)
		*irPath = lowered
	}

	doc, err := loadIR(*irPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sast: %v\n", err)
		return exitError
	}

	pol, err := policy.LoadFile(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sast: %v\n", err)
		return exitError
	}

	base, err := baseline.Load(*baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sast: %v\n", err)
		return exitError
	}

	changed, err := loadChanged(*changedPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sast: %v\n", err)
		return exitError
	}

	res := scan.Run(doc, model.Builtin(), pol)
	res.Baseline = base
	res.Changed = changed

	// Writing a baseline is a separate job from judging a codebase: it records what is
	// there and says nothing about whether any of it is acceptable, so it never fails
	// the run it was invoked on.
	if *writeBaseline != "" {
		if err := recordBaseline(*writeBaseline, res); err != nil {
			fmt.Fprintf(os.Stderr, "sast: %v\n", err)
			return exitError
		}
		fmt.Fprintf(os.Stderr, "sast: recorded %d finding(s) to %s\n", len(res.Taint.Findings), *writeBaseline)
		return exitClean
	}

	if err := render(*format, res); err != nil {
		fmt.Fprintf(os.Stderr, "sast: %v\n", err)
		return exitError
	}

	// A capability gap is reported distinctly from a clean scan, all the way out to
	// the pipeline's exit status (ADR-003).
	if res.NotApplicable() {
		return exitNotApplicable
	}
	return gateStatus(*failOn, res)
}

// loadChanged reads the set of paths a run is being asked about, as produced by
// `git diff --name-only`. Paths are matched against the IR, which is root-relative, so
// the file must be written from the same directory the scan is rooted at.
//
// An empty file is a real answer and not the same as no file: it says this change
// touched nothing, so nothing can gate. Returning nil there would silently widen the
// run back to the whole tree.
func loadChanged(path string) (map[string]bool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read changed-files list: %w", err)
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if p := strings.TrimSpace(line); p != "" {
			out[p] = true
		}
	}
	return out, nil
}

// recordBaseline writes every finding this run produced, including the ones that would
// not have gated. A baseline that recorded only gating findings would quietly promote
// the rest into "new" on the next run that raised their confidence.
func recordBaseline(path string, res scan.Result) error {
	entries := make([]baseline.Entry, 0, len(res.Taint.Findings))
	for _, f := range res.Taint.Findings {
		entries = append(entries, baseline.Entry{
			Fingerprint: f.Fingerprint(),
			CWE:         f.CWE,
			Policy:      f.Analysis,
			EntryPoint:  f.EntryPoint,
			Sink:        fmt.Sprintf("%s at %s", f.SinkSymbol, f.SinkLoc),
			Note:        f.Class,
		})
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create baseline: %w", err)
	}
	defer f.Close()
	return baseline.Write(f, entries)
}

func loadIR(path string) (*ir.IR, error) {
	if path == "-" {
		return ir.Load(os.Stdin)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open IR: %w", err)
	}
	defer f.Close()
	return ir.Load(f)
}

func render(format string, res scan.Result) error {
	switch format {
	case "text":
		return report.Text(os.Stdout, res)
	case "sarif":
		return report.SARIF(os.Stdout, res, version)
	default:
		return fmt.Errorf("unknown format %q (want text or sarif)", format)
	}
}

func gateStatus(failOn string, res scan.Result) int {
	switch failOn {
	case "never":
		return exitClean
	case "any":
		if res.AnyFindings() {
			return exitGating
		}
	default: // "gating": confidence decides, not severity (ADR-005)
		if res.Gating() {
			return exitGating
		}
	}
	return exitClean
}
