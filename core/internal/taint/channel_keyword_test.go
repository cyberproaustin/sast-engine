package taint

import (
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
)

func TestChannelArgsUseOnlyDeclaredExternalKeywords(t *testing.T) {
	call := &ir.Call{Args: []ir.Arg{
		{Index: 1, ValueID: "positional"},
		{Name: "data", ValueID: "data"},
		{Name: "json", ValueID: "json"},
		{Name: "headers", ValueID: "headers"},
	}}
	channel := model.Channel{
		Symbol:          "requests.post",
		ArgIndex:        []int{1},
		RequiredKeyword: map[string]int{"data": 1, "json": 1},
	}

	got := channelArgs(call, channel, channel.ArgIndex)
	if len(got) != 3 {
		t.Fatalf("positional, data, and json should reach the channel; got %+v", got)
	}
	for _, arg := range got {
		if arg.Index != 1 {
			t.Errorf("the declared keyword should retain the channel's positional identity; got %+v", arg)
		}
		if arg.ValueID == "headers" {
			t.Error("an undeclared keyword must not satisfy a channel index")
		}
	}
}

func TestChannelArgsDoNotGiveMethodNamesAnImplicitSignature(t *testing.T) {
	call := &ir.Call{Args: []ir.Arg{{Name: "data", ValueID: "named"}}}
	channel := model.Channel{
		Method:          "post",
		ArgIndex:        []int{1},
		RequiredKeyword: map[string]int{"data": 1},
	}

	if got := channelArgs(call, channel, channel.ArgIndex); len(got) != 0 {
		t.Fatalf("only an external symbol may declare keyword binding; got %+v", got)
	}
	if call.Args[0].At(1) {
		t.Fatal("Arg.At must continue refusing to infer a keyword's position")
	}
}

func TestBuiltinChannelKeywordsNameAnExistingExternalIndex(t *testing.T) {
	for _, channel := range model.Builtin().Channels {
		for name, index := range channel.RequiredKeyword {
			if channel.Symbol == "" {
				t.Errorf("%s declares keyword %q without an external symbol", channel.ID, name)
			}
			if !containsIndex(channel.ArgIndex, index) {
				t.Errorf("%s %s maps keyword %q to undeclared argument %d", channel.ID, channel.Symbol, name, index)
			}
		}
	}
}

func TestBuiltinChannelsDeclarePythonKeywordSpellings(t *testing.T) {
	want := []struct {
		channel string
		symbol  string
		name    string
		index   int
	}{
		{channel: "outbound-http", symbol: "requests.post", name: "data", index: 1},
		{channel: "outbound-http", symbol: "requests.post", name: "json", index: 1},
		{channel: "process-arguments", symbol: "subprocess.run", name: "args", index: 0},
		{channel: "filesystem-path", symbol: "builtins.open", name: "file", index: 0},
		{channel: "object-deserializer", symbol: "yaml.load", name: "stream", index: 0},
	}

	channels := model.Builtin().Channels
	for _, required := range want {
		found := false
		for _, channel := range channels {
			if channel.ID != required.channel || channel.Symbol != required.symbol {
				continue
			}
			if index, ok := channel.RequiredKeyword[required.name]; ok && index == required.index {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s %s does not map keyword %q to argument %d", required.channel, required.symbol, required.name, required.index)
		}
	}
}
