package flow

import (
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
)

func TestZZProbe(t *testing.T) {
	path := os.Getenv("PROBE_IR")
	if path == "" {
		t.Skip("no PROBE_IR")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := ir.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	rep := JoinViews(d)
	fmt.Printf("views=%d renders=%d resolved=%d sinks=%d\n", rep.Views, rep.Renders, rep.Resolved, rep.Sinks)
	want := os.Getenv("PROBE_VIEW")
	if want == "" {
		return
	}
	for _, v := range d.Views {
		if v.ID != want {
			continue
		}
		fmt.Printf("VIEW %s extends=%v includes=%+v\n", v.ID, v.Extends, v.Includes)
		for _, r := range v.Reads {
			fmt.Printf("  read path=%q escaped=%v ctx=%q loc=%s removed=%v\n", r.Path, r.Escaped, r.Context, r.Loc.String(), r.RemovedAt)
		}
	}
	names := []string{}
	for _, r := range d.Renders {
		names = append(names, fmt.Sprintf("view=%q name=%q fromParam=%q fwd=%v fn=%s loc=%s binds=%d", r.View, r.Name, r.FromParam, r.ForwardsKeywords, r.FunctionID, r.Loc.String(), len(r.Bindings)))
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Println("RENDER", n)
	}
}
