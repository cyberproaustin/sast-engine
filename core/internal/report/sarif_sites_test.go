package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/scan"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

func TestSARIFCarriesEveryConsolidatedSiteAndPath(t *testing.T) {
	path := func(line int) []taint.Hop {
		return []taint.Hop{{Loc: ir.Loc{File: "app.js", Line: line}, Description: "reaches response"}}
	}
	f := taint.Finding{
		Analysis: "error-exposure", CWE: "CWE-209", Class: "Failure detail exposed",
		Message: "internal detail leaves the system", SourceLabel: "error",
		SinkLoc: ir.Loc{File: "app.js", Line: 10}, Path: path(10),
		RelatedSites: []taint.Site{
			{Loc: ir.Loc{File: "app.js", Line: 20}, Path: path(20)},
			{Loc: ir.Loc{File: "app.js", Line: 30}, Path: path(30)},
		},
	}
	res := scan.Result{
		IR:    &ir.IR{IRVersion: "0.1", Frontend: ir.Frontend{Name: "test"}},
		Taint: taint.Result{Applicable: true, Findings: []taint.Finding{f}},
	}
	var buf bytes.Buffer
	if err := SARIF(&buf, res, "test"); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	got := doc.Runs[0].Results[0]
	if len(got.Locations) != 3 || len(got.RelatedLocations) != 2 || len(got.CodeFlows) != 3 {
		t.Fatalf("locations=%d relatedLocations=%d codeFlows=%d, want 3/2/3",
			len(got.Locations), len(got.RelatedLocations), len(got.CodeFlows))
	}
}
