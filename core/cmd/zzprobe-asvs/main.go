// Temporary measurement probe (deleted before the change ships).
package main

import (
	"fmt"
	"os"

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
	for _, fd := range res.Taint.Findings {
		fmt.Printf("%s\t%s\tclass=%s\tvis=%s\tchan=%s\ttrust=%s\tanchored=%v\tdependsOnUse=%q\tconf=%s\t%s:%d\tep=%s\n",
			fd.CWE, fd.Analysis, fd.Class, fd.Visibility, fd.ChannelID, fd.SourceTrust(),
			fd.EntryAnchored, fd.DependsOnUse, fd.Confidence, fd.SinkLoc.File, fd.SinkLoc.Line, fd.EntryPoint)
	}
}
