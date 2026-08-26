package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/cyberproaustin/sast-engine/core/internal/assertion"
	"github.com/cyberproaustin/sast-engine/core/internal/expectation"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/scan"
	"github.com/cyberproaustin/sast-engine/core/internal/surface"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// SARIF 2.1.0, minimal but valid. The evidence path is emitted as a codeFlow so the
// justification survives into any consumer rather than living only in our own output.

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
	Properties  map[string]any    `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID           string          `json:"ruleId"`
	Level            string          `json:"level"`
	Message          sarifText       `json:"message"`
	Locations        []sarifLocation `json:"locations"`
	RelatedLocations []sarifLocation `json:"relatedLocations,omitempty"`
	CodeFlows        []sarifCodeFlow `json:"codeFlows,omitempty"`
	// PartialFingerprints is SARIF's own mechanism for matching a finding to its
	// previous self across runs. Emitting it here means a consumer that already knows
	// how to track findings — GitHub code scanning, among others — does not need this
	// engine's baseline file to do it.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	ID               int           `json:"id,omitempty"`
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
	Message          *sarifText    `json:"message,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadFlowLocation `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location sarifLocation `json:"location"`
}

// SARIF writes the result as a SARIF 2.1.0 document.
func SARIF(w io.Writer, scanRes scan.Result, toolVersion string) error {
	d := scanRes.IR
	res := scanRes.Taint

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:    "sast-engine",
			Version: toolVersion,
			Rules:   rulesFor(scanRes),
		}},
		Results: make([]sarifResult, 0, len(res.Findings)+len(scanRes.Expectation.Findings)),
		Properties: map[string]any{
			"frontend":            d.Frontend.Name,
			"frontendVersion":     d.Frontend.Version,
			"irVersion":           d.IRVersion,
			"analysisApplicable":  res.Applicable,
			"missingCapabilities": res.MissingCapabilities,
			// The enumerated surface travels with the results (ADR-009), so a
			// consumer can see what was examined and not only what was found.
			"surface":               surfaceProps(scanRes),
			"nonApplicationSurface": entryProps(scanRes.Surface.NonApplicationEntries),
			// The coverage map travels with the results, so a consumer can see what
			// was NOT claimed as well as what was (ADR-007).
			"coverage": coverageProps(assertion.Evaluate(scanRes)),
		},
	}

	// An analysis that could not run is recorded as an unsuccessful invocation, so a
	// consumer cannot read the empty result set as a clean scan (ADR-003).
	if !res.Applicable {
		run.Invocations = []sarifInvocation{{
			ExecutionSuccessful: false,
			ToolExecutionNotifications: []sarifNotification{{
				Level: "error",
				Message: sarifText{Text: fmt.Sprintf(
					"analysis taint-flow did not run: frontend does not declare %v. This is not a clean result.",
					res.MissingCapabilities)},
			}},
		}}
	} else {
		run.Invocations = []sarifInvocation{{ExecutionSuccessful: true}}
	}

	for _, f := range res.Findings {
		run.Results = append(run.Results, sarifResult{
			RuleID:              f.CWE,
			Level:               levelFor(f),
			Message:             sarifText{Text: fmt.Sprintf("%s: %s (source: %s)", f.Class, f.Message, f.SourceLabel)},
			Locations:           locationsOf(f),
			RelatedLocations:    relatedLocationsOf(f),
			CodeFlows:           codeFlowsOf(f),
			PartialFingerprints: map[string]string{"sastEngine/v1": f.Fingerprint()},
			Properties: map[string]any{
				"confidence":  string(f.Confidence),
				"gating":      scanRes.Gates(f),
				"baselined":   !scanRes.IsNew(f),
				"entryPoint":  f.EntryPoint,
				"anchored":    f.EntryAnchored,
				"sinkSymbol":  f.SinkSymbol,
				"sinkContext": f.SinkContext,
				"owaspTop10":  assertion.Top10For(f.CWE),
				"sanitizers":  sanitizerProps(f),
				"provenance":  f.Provenance,
				"entryTrust":  string(f.SourceTrust()),
			},
		})
	}

	for _, f := range scanRes.Expectation.Findings {
		level := "warning" // inferred expectations never gate (ADR-010)
		if f.Gates {
			level = "error"
		}
		run.Results = append(run.Results, sarifResult{
			RuleID:    f.CWE,
			Level:     level,
			Message:   sarifText{Text: f.Message},
			Locations: []sarifLocation{locationOf(f.EntryLoc, "")},
			Properties: map[string]any{
				"gating":             f.Gates,
				"expectationOrigin":  f.Origin,
				"entryPoint":         f.EntryPoint,
				"group":              f.Group,
				"missingControl":     f.MissingName,
				"controlKind":        f.ControlKind,
				"peers":              f.Peers,
				"conformingPeers":    f.Conforming,
				"conformingEntryIDs": f.ConformingList,
			},
		})
	}

	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func coverageProps(rep assertion.Report) map[string]any {
	reqs := make([]map[string]any, 0, len(rep.Requirements))
	for _, e := range rep.Requirements {
		reqs = append(reqs, map[string]any{
			"id": e.Requirement.ID, "title": e.Requirement.Title,
			"state": string(e.State), "findings": e.Findings, "reason": e.Reason,
		})
	}
	rollup := make([]map[string]any, 0, len(rep.Rollup))
	for _, r := range rep.Rollup {
		rollup = append(rollup, map[string]any{
			"category": r.Category, "findings": r.Findings, "cwes": r.CWEs,
		})
	}
	return map[string]any{
		"requirements": reqs,
		"owaspTop10":   rollup,
		"unmappedCWEs": rep.Unmapped,
	}
}

func surfaceProps(r scan.Result) []map[string]any {
	return entryProps(r.Surface.Entries)
}

func entryProps(entries []surface.EntryFacts) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		controls := make([]string, 0, len(e.Controls))
		for _, c := range e.Controls {
			controls = append(controls, c.Name)
		}
		out = append(out, map[string]any{
			"entryPoint": e.Label(),
			"kind":       e.EntryPoint.Kind,
			"trust":      string(e.TrustLevel()),
			"group":      e.Group,
			"controls":   controls,
			"provenance": e.Provenance,
			"detail":     e.EntryPoint.Detail,
		})
	}
	return out
}

func expectationRule(f expectation.Finding) sarifRule {
	return sarifRule{
		ID:               f.CWE,
		Name:             f.Class,
		ShortDescription: sarifText{Text: "Entry point does not meet an access-control expectation"},
		Properties:       map[string]any{"expectationOrigin": f.Origin},
	}
}

func rulesFor(r scan.Result) []sarifRule {
	seen := make(map[string]bool)
	rules := make([]sarifRule, 0, 4)
	for _, f := range r.Expectation.Findings {
		if seen[f.CWE] {
			continue
		}
		seen[f.CWE] = true
		rules = append(rules, expectationRule(f))
	}
	for _, f := range r.Taint.Findings {
		if seen[f.CWE] {
			continue
		}
		seen[f.CWE] = true
		rules = append(rules, sarifRule{
			ID:               f.CWE,
			Name:             f.Class,
			ShortDescription: sarifText{Text: f.Message},
			Properties:       map[string]any{"context": f.SinkContext},
		})
	}
	return rules
}

func codeFlowOf(f taint.Finding) sarifCodeFlow {
	return codeFlowForPath(f.Path)
}

func codeFlowForPath(path []taint.Hop) sarifCodeFlow {
	locs := make([]sarifThreadFlowLocation, 0, len(path))
	for _, h := range path {
		locs = append(locs, sarifThreadFlowLocation{Location: locationOf(h.Loc, h.Description)})
	}
	return sarifCodeFlow{ThreadFlows: []sarifThreadFlow{{Locations: locs}}}
}

func locationsOf(f taint.Finding) []sarifLocation {
	locations := make([]sarifLocation, 0, 1+len(f.RelatedSites))
	locations = append(locations, locationOf(primarySiteLoc(f), ""))
	for _, site := range f.RelatedSites {
		locations = append(locations, locationOf(site.Loc, "same weakness at another syntactic site"))
	}
	return locations
}

func primarySiteLoc(f taint.Finding) ir.Loc {
	if len(f.Path) > 1 {
		h := f.Path[len(f.Path)-2]
		if h.Kind == "enclose" && h.Loc.File == f.SinkLoc.File {
			return h.Loc
		}
	}
	return f.SinkLoc
}

func relatedLocationsOf(f taint.Finding) []sarifLocation {
	locations := make([]sarifLocation, 0, len(f.RelatedSites))
	for i, site := range f.RelatedSites {
		loc := locationOf(site.Loc, "same rule, sink function and value origin")
		loc.ID = i + 1
		locations = append(locations, loc)
	}
	return locations
}

func codeFlowsOf(f taint.Finding) []sarifCodeFlow {
	flows := make([]sarifCodeFlow, 0, 1+len(f.RelatedSites))
	flows = append(flows, codeFlowOf(f))
	for _, site := range f.RelatedSites {
		flows = append(flows, codeFlowForPath(site.Path))
	}
	return flows
}

func locationOf(l ir.Loc, message string) sarifLocation {
	loc := sarifLocation{
		PhysicalLocation: sarifPhysical{
			ArtifactLocation: sarifArtifact{URI: l.File},
			Region:           sarifRegion{StartLine: l.Line, StartColumn: l.Column},
		},
	}
	if message != "" {
		loc.Message = &sarifText{Text: message}
	}
	return loc
}

func sanitizerProps(f taint.Finding) []map[string]any {
	out := make([]map[string]any, 0, len(f.Sanitizers))
	for _, s := range f.Sanitizers {
		out = append(out, map[string]any{
			"symbol":          s.Symbol,
			"clearedForSink":  s.Clears,
			"requiredContext": s.Required,
			"note":            s.Note,
		})
	}
	return out
}

// levelFor maps the engine's own judgement — not severity — onto SARIF levels (ADR-005).
//
// It used to read confidence alone, which measured badly: across ten repositories the
// engine emitted 82 findings at level error whose own gating property was false, against
// 41 that actually gated. Two thirds of the output arrived at the highest level available
// for findings the engine had already decided not to fail a build on, and every consumer
// of SARIF — a code scanning dashboard, a CI check, a maintainer — reads error as "act on
// this".
//
// A finding in a test module drops the whole way to note. It is in the repository exactly
// as its reason says, and it is still not a production defect; 34 of 59 hardcoded-secret
// findings in that batch were test fixtures, and flattening that distinction into error is
// how a real credential in a test would have been lost among them.
//
// Trust ranks the same way and for the same reason. `error` is read by every consumer as
// "a caller can do this to you"; a management command's own argument and a process's own
// environment are reached by whoever already has the host, and a cron job is reached by
// nobody at all. Those are real findings and they are not that claim, so they publish at
// warning — while a scheduled job reading a column an HTTP request wrote still publishes
// at error, because the trust travels with the source and that source is remote.
func levelFor(f taint.Finding) string {
	switch {
	case f.InTestModule || f.Provenance != "":
		return "note"
	case f.SourceTrust() != ir.Remote:
		return "warning"
	case f.Actionable():
		return "error"
	default:
		return "warning"
	}
}
