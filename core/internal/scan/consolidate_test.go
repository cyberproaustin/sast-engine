package scan

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

func TestFlowBranchesBecomeSitesOfOneWeakness(t *testing.T) {
	locs := []ir.Loc{{File: "app.js", Line: 10}, {File: "app.js", Line: 20}, {File: "app.js", Line: 30}}
	fn := &ir.Function{ID: "send", Name: "sendHttpError", Module: "app.js"}
	for i, loc := range locs {
		fn.Calls = append(fn.Calls, &ir.Call{ID: string(rune('a' + i)), Loc: loc})
	}
	doc := &ir.IR{Functions: []*ir.Function{fn}}
	var findings []taint.Finding
	for i, loc := range locs {
		findings = append(findings, taint.Finding{
			Analysis: "error-exposure", CWE: "CWE-209", ChannelID: "http-response",
			DataClass: "failure-detail", EntryPoint: "GET /badge", SourceLabel: "error",
			SourceLoc: ir.Loc{File: "router.js", Line: 8}, SinkLoc: loc,
			SinkSymbol: []string{"res.status(503).json", "res.status(404).json", "res.status(403).json"}[i],
			Confidence: taint.Medium,
			Path:       []taint.Hop{{Loc: loc, Description: "reaches response"}},
		})
	}
	wantFingerprint := findings[0].Fingerprint()

	got := collapseFlowFindings(doc, findings)
	if len(got) != 1 {
		t.Fatalf("three branches produced %d findings, want one", len(got))
	}
	if len(got[0].RelatedSites) != 2 {
		t.Fatalf("kept %d secondary sites, want two", len(got[0].RelatedSites))
	}
	if got[0].Fingerprint() != wantFingerprint {
		t.Fatalf("consolidation changed fingerprint from %s to %s", wantFingerprint, got[0].Fingerprint())
	}
}

func TestDifferentSinkOperationsRemainDifferentWeaknesses(t *testing.T) {
	fn := &ir.Function{ID: "ping", Name: "ping", Module: "app.py", Calls: []*ir.Call{
		{ID: "call", Loc: ir.Loc{File: "app.py", Line: 10}},
		{ID: "popen", Loc: ir.Loc{File: "app.py", Line: 11}},
	}}
	common := taint.Finding{
		Analysis: "command-injection", CWE: "CWE-78", ChannelID: "shell",
		DataClass: "caller-input", EntryPoint: "GET /ping", SourceLabel: "request.args.host",
		SourceLoc: ir.Loc{File: "app.py", Line: 8},
	}
	call, popen := common, common
	call.SinkLoc, call.SinkSymbol = fn.Calls[0].Loc, "subprocess.call"
	popen.SinkLoc, popen.SinkSymbol = fn.Calls[1].Loc, "subprocess.Popen"

	got := collapseFlowFindings(&ir.IR{Functions: []*ir.Function{fn}}, []taint.Finding{call, popen})
	if len(got) != 2 {
		t.Fatalf("two different sink operations produced %d findings, want two", len(got))
	}
}

func TestDifferentValuesDerivedFromOneRootRemainDifferentWeaknesses(t *testing.T) {
	fn := &ir.Function{ID: "download", Name: "download", Module: "app.js", Calls: []*ir.Call{
		{ID: "content-type", Loc: ir.Loc{File: "app.js", Line: 10}},
		{ID: "filename", Loc: ir.Loc{File: "app.js", Line: 20}},
	}}
	common := taint.Finding{
		Analysis: "header-injection", CWE: "CWE-93", ChannelID: "http-header",
		DataClass: "caller-input", EntryPoint: "GET /download", SourceLabel: "req.query.token",
		SourceLoc: ir.Loc{File: "app.js", Line: 3}, SinkSymbol: "res.setHeader",
	}
	contentType, filename := common, common
	contentType.SinkLoc = fn.Calls[0].Loc
	contentType.Path = []taint.Hop{{Kind: "property", Description: "property `contentType`"}, {Description: "reaches res.setHeader"}}
	filename.SinkLoc = fn.Calls[1].Loc
	filename.Path = []taint.Hop{{Kind: "property", Description: "property `filePath`"}, {Description: "reaches res.setHeader"}}

	got := collapseFlowFindings(&ir.IR{Functions: []*ir.Function{fn}}, []taint.Finding{contentType, filename})
	if len(got) != 2 {
		t.Fatalf("two values derived from one root produced %d findings, want two", len(got))
	}
}

// The existing fingerprint collision is the boundary this change must not cross. These
// calls stand for juice-shop's /ftp, /encryptionkeys and /support/logs listings: their
// legacy fingerprints collide because an Always call shape records the called symbol, not
// its distinct directory argument. Consolidation is limited to flows and exact literals,
// so the three findings remain visible until that separate fingerprint defect is fixed.
func TestDistinctCallShapesAreNotConsolidatedByCollidingFingerprint(t *testing.T) {
	fn := &ir.Function{ID: "module", Name: "<module>", Module: "app.js"}
	for i, line := range []int{10, 20, 30} {
		fn.Calls = append(fn.Calls, &ir.Call{
			ID: string(rune('a' + i)), Loc: ir.Loc{File: "app.js", Line: line},
			Callee: ir.Callee{Symbol: "serve-index.default", Resolution: ir.Resolved},
		})
	}
	doc := &ir.IR{
		IRVersion: "0.1", Frontend: ir.Frontend{Name: "test"},
		Modules: []ir.Module{{ID: "app.js", Path: "app.js"}}, Functions: []*ir.Function{fn},
	}
	res := Run(doc, model.Builtin(), nil)
	var listings []taint.Finding
	for _, f := range res.Taint.Findings {
		if f.Analysis == "directory-listing" {
			listings = append(listings, f)
		}
	}
	if len(listings) != 3 {
		t.Fatalf("three directory listings produced %d findings, want three", len(listings))
	}
	if listings[0].Fingerprint() != listings[1].Fingerprint() || listings[1].Fingerprint() != listings[2].Fingerprint() {
		t.Fatal("fixture no longer exercises the known legacy fingerprint collision")
	}
}
