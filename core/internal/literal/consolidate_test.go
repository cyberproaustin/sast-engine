package literal

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
)

func TestIdenticalLiteralInOneFunctionIsOneFinding(t *testing.T) {
	const key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	doc := &ir.IR{
		Modules: []ir.Module{{ID: "app.js", Path: "app.js"}},
		Functions: []*ir.Function{{
			ID: "fixture", Name: "fixture", Module: "app.js",
			Values: []*ir.Value{
				{ID: "input", Kind: ir.ValueLiteral, Literal: key, Loc: ir.Loc{File: "app.js", Line: 4}},
				{ID: "expected", Kind: ir.ValueLiteral, Literal: key, Loc: ir.Loc{File: "app.js", Line: 7}},
			},
		}},
	}

	got := Analyze(doc, model.Builtin())
	if len(got) != 1 {
		t.Fatalf("identical input and expected literals produced %d findings, want one", len(got))
	}
	if len(got[0].RelatedSites) != 1 || got[0].RelatedSites[0].Loc.Line != 7 {
		t.Fatalf("secondary literal site = %+v, want app.js:7", got[0].RelatedSites)
	}
}
