package guard

import (
	"fmt"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/cfg"
	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// forwardedCredentials reports an inbound header collection handed to an outbound
// request after the request URL's authority has been replaced. Credential names are
// checked as removals rather than reads: copying a Headers object never projects Cookie
// or Authorization into separate values, but those fields are present unless the program
// mutates the collection to delete them.
func forwardedCredentials(d *ir.IR, rule model.GuardRule, input taint.Classified) []taint.Finding {
	ix := ir.NewIndex(d)
	var out []taint.Finding
	for _, fn := range d.Functions {
		graph := cfg.Build(fn)
		if graph == nil {
			continue
		}
		for _, call := range fn.Calls {
			if !oneOfFold(call.Callee.Symbol, rule.CredentialForwarding.OutboundSymbols) {
				continue
			}
			target := callArg(call, 0)
			options := callArg(call, 1)
			headers := objectEntryBehind(ix, fn, options, rule.CredentialForwarding.HeadersKey, map[string]bool{}, 0)
			source, origin, ok := inboundHeadersSource(ix, fn, headers, input)
			if headers == "" || !ok {
				continue
			}
			authority := changedAuthority(ix, fn, graph, call, target, rule.CredentialForwarding.AuthorityPaths)
			if authority == nil || credentialsRemoved(fn, graph, call, headers, rule.CredentialForwarding) {
				continue
			}
			out = append(out, forwardedCredentialFinding(ix, fn, call, authority, source, origin, rule))
		}
	}
	return out
}

// inboundHeadersSource asks for the constructor boundary, not just taint on the final
// collection. A caller-controlled object can be used as a hand-built header map without
// containing the ambient Cookie header; `new Headers(request.headers)` is the operation
// that copies the complete inbound set and makes absence of a removal meaningful.
func inboundHeadersSource(ix *ir.Index, fn *ir.Function, headers string,
	input taint.Classified,
) (string, taint.Origin, bool) {
	if headers == "" {
		return "", taint.Origin{}, false
	}
	for _, call := range fn.Calls {
		if call.ResultID == "" || !sameAssignedValue(fn, headers, call.ResultID) ||
			!strings.EqualFold(symbolLeaf(call.Callee.Symbol), "Headers") {
			continue
		}
		source := callArg(call, 0)
		value := ix.ValueByID[source]
		origin, ok := input.Origin[source]
		if value == nil || value.Kind != ir.ValueProperty ||
			!strings.EqualFold(symbolLeaf(value.Path), "headers") || !input.Values[source] || !ok {
			continue
		}
		return source, origin, true
	}
	return "", taint.Origin{}, false
}

func symbolLeaf(symbol string) string {
	parts := strings.FieldsFunc(symbol, func(r rune) bool { return r == '.' || r == ':' || r == '/' })
	if len(parts) == 0 {
		return symbol
	}
	return parts[len(parts)-1]
}

// objectEntryBehind follows plain bindings to the finite object literal filed under an
// options argument. A computed object or spread is not a complete key set and answers
// nothing, which is the same absence boundary every call-shape option rule uses.
func objectEntryBehind(ix *ir.Index, fn *ir.Function, id, key string, seen map[string]bool, depth int) string {
	if id == "" || seen[id] || depth >= 10 {
		return ""
	}
	seen[id] = true
	if value := ix.ValueByID[id]; value != nil {
		for _, entry := range value.Entries {
			if strings.EqualFold(entry.Key, key) {
				return entry.ValueID
			}
		}
	}
	for _, flow := range fn.Flows {
		if flow.To == id && flow.Kind == "assign" {
			if found := objectEntryBehind(ix, fn, flow.From, key, seen, depth+1); found != "" {
				return found
			}
		}
	}
	return ""
}

// changedAuthority returns the write proving this URL no longer names the request's own
// authority. Deliberately narrower than "an absolute URL": a configured absolute URL may
// name this deployment. Cloning request.url and then replacing host/hostname/origin is an
// affirmative relation between the two destinations and is the shape under review.
func changedAuthority(ix *ir.Index, fn *ir.Function, graph *cfg.Graph, outbound *ir.Call,
	target string, paths []string,
) *ir.Write {
	for i := range fn.Writes {
		write := &fn.Writes[i]
		if !oneOfFold(write.Path, paths) || !sameAssignedValue(fn, target, write.Base) ||
			!writeOrdered(graph, write.Block, write.Loc, outbound) {
			continue
		}
		// Assigning the URL's own host back to it is the explicit same-host near miss.
		if value := ix.ValueByID[write.From]; value != nil && value.Kind == ir.ValueProperty &&
			oneOfFold(value.Path, paths) && sameAssignedValue(fn, target, value.Base) {
			continue
		}
		return write
	}
	return nil
}

func writeOrdered(graph *cfg.Graph, block string, loc ir.Loc, after *ir.Call) bool {
	if block == "" || after.Block == "" || !graph.Dominates(block, after.Block) {
		return false
	}
	if block != after.Block {
		return true
	}
	return loc.Line < after.Loc.Line || (loc.Line == after.Loc.Line && loc.Column < after.Loc.Column)
}

func credentialsRemoved(fn *ir.Function, graph *cfg.Graph, outbound *ir.Call, headers string,
	shape *model.CredentialForwardingGuard,
) bool {
	removed := map[string]bool{}
	for _, call := range fn.Calls {
		if !oneOfFold(call.Method, shape.RemoveMethods) ||
			!sameAssignedValue(fn, headers, call.ReceiverID) || !ordered(graph, call, outbound) {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(call.ArgLiterals[0]))
		for _, credential := range shape.CredentialNames {
			if strings.EqualFold(name, credential) {
				removed[strings.ToLower(credential)] = true
			}
		}
	}
	return len(removed) == len(shape.CredentialNames)
}

func forwardedCredentialFinding(ix *ir.Index, fn *ir.Function, sink *ir.Call, authority *ir.Write,
	source string, origin taint.Origin, rule model.GuardRule,
) taint.Finding {
	sourceLoc := sink.Loc
	if value := ix.ValueByID[source]; value != nil {
		sourceLoc = value.Loc
	}
	return taint.Finding{
		Analysis:      rule.ID,
		DataClass:     "credential-bearing-header-set",
		ChannelID:     rule.ID,
		Visibility:    "thirdparty",
		Class:         rule.Finding,
		CWE:           rule.CWE,
		Message:       rule.Reason,
		Confidence:    taint.High,
		SourceLoc:     sourceLoc,
		SourceLabel:   origin.Label,
		EntryPoint:    origin.EntryPoint,
		EntryMethod:   origin.Method,
		EntryPath:     origin.Path,
		EntryAnchored: origin.Anchored,
		EntryTrust:    origin.Trust,
		SinkLoc:       sink.Loc,
		SinkFunction:  fn.Name,
		SinkSymbol:    callName(ix, sink),
		SinkArgIndex:  1,
		SinkRational:  rule.Rationale,
		Path: []taint.Hop{
			{Loc: sourceLoc, Description: origin.Label + " is copied as one header collection", Resolution: ir.Resolved},
			{Loc: authority.Loc, Description: fmt.Sprintf("the outbound URL's %s is replaced", authority.Path), Resolution: ir.Resolved},
			{Loc: sink.Loc, Description: fmt.Sprintf("the collection reaches %s() without both Cookie and Authorization removed", callName(ix, sink)), Resolution: sink.Callee.Resolution},
		},
	}
}
