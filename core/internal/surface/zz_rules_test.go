package surface

import (
	"fmt"
	"os"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/model"
)

func TestZZRules(t *testing.T) {
	if os.Getenv("DIAG_RULES") == "" {
		t.Skip("set DIAG_RULES")
	}
	m := model.Builtin()
	for _, c := range m.Classifications {
		if c.Class != m.UntrustedClass() {
			continue
		}
		for _, r := range c.Rules {
			fmt.Printf("match=%-22s fw=%-22s entryKind=%-14s paramIdx=%d paths=%v symbol=%s kind=%s exact=%v\n",
				r.Match, r.Framework, r.EntryKind, r.ParamIndex, r.Paths, r.Symbol, r.ValueKind, r.ExactPath)
		}
	}
}
