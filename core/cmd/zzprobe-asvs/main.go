// Temporary measurement probe (deleted before the change ships).
package main

import (
	"fmt"
	"os"

	"github.com/cyberproaustin/sast-engine/core/internal/assertion"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/scan"
)

func main() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	d, err := ir.Load(f)
	f.Close()
	if err != nil {
		panic(err)
	}
	res := scan.Run(d, model.Builtin(), nil)
	c := res.Surface.Completeness
	fmt.Printf("entries=%d remote=%d input=%d unreached=%d nonprod=%d suspect=%v ratio=%.3f\n",
		len(res.Surface.Entries), res.Surface.RemoteEntries(), c.InputFunctions,
		c.UnreachedInputFunctions, c.NonProductionInputFunctions,
		c.Suspect(res.Surface.RemoteEntries()),
		float64(c.UnreachedInputFunctions)/float64(max(c.InputFunctions, 1)))
	for _, g := range c.Unreached {
		fmt.Printf("  [%s] %d modules\n", g.Cause, len(g.Modules))
		for _, m := range g.Modules {
			fmt.Printf("     %-60s %d\n", m.Dir, m.Count)
		}
		for _, u := range g.Sample {
			fmt.Printf("     e.g. %s  %s:%d  %s\n", u.Name, u.Loc.File, u.Loc.Line, u.Detail)
		}
	}
	for _, e := range assertion.Evaluate(res).Requirements {
		fmt.Printf("  %-10s %-14s %s\n", e.Requirement.ID, e.State, e.Reason)
	}
}
