package guard

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/taint"
)

// csrfStateChanges reports the two handler-local spellings the population judgement
// cannot see: a declaration that removes CSRF enforcement, and a safe-method route that
// writes state before any method-dependent branch can refuse it.
//
// The persistence vocabulary is not repeated here. Model.StoreWriteAt is the answer the
// second-order flow already uses for ORM and session writes. One resolved helper edge is
// followed because both measured handlers put persistence there; going farther reached
// framework initialization several layers below otherwise read-only configuration calls
// and produced a false state-change claim.
func csrfStateChanges(d *ir.IR, m model.Model, rule model.GuardRule) []taint.Finding {
	ix := ir.NewIndex(d)
	allWrites := stateWriteReachability(d, m, false)
	entryWrites := stateWriteReachability(d, m, true)
	var out []taint.Finding

	for i := range d.EntryPoints {
		ep := &d.EntryPoints[i]
		if ep.Kind != "http-route" || ep.FunctionID == "" ||
			!oneOfFold(ep.Framework, rule.CSRFStateChange.Frameworks) {
			continue
		}
		fn := ix.FuncByID[ep.FunctionID]
		if fn == nil {
			continue
		}
		exempt := strings.EqualFold(ep.Detail["csrfExempt"], "true")
		if !exempt && strings.EqualFold(ep.Detail["methodRestricted"], "true") {
			continue
		}
		if !exempt && !oneOfFold(ep.Detail["method"], rule.CSRFStateChange.SafeMethods) {
			continue
		}

		// Only work started in the entry block is claimed. A Django URLconf says ANY
		// even when the function later branches on request.method; a write in that arm
		// is not reachable by every method and therefore supplies no evidence here.
		writes := entryWrites
		if exempt {
			writes = allWrites
		}
		trigger := firstStateChangingCall(fn, writes, m, !exempt)
		if trigger == nil {
			continue
		}
		out = append(out, csrfFinding(ix, fn, ep, trigger, exempt, rule))
	}
	return out
}

// stateWriteReachability maps a function to a persistent write in that function. The
// caller consumes this map across one resolved edge; it intentionally is not a transitive
// closure, because an initialization write three library helpers below a read is not the
// request operation the handler starts.
func stateWriteReachability(d *ir.IR, m model.Model, entryOnly bool) map[string]*ir.Call {
	writes := map[string]*ir.Call{}
	for _, fn := range d.Functions {
		for _, call := range fn.Calls {
			store, ok := m.StoreWriteAt(call.Callee.Symbol, call.Method, call.ReceiverType)
			if ok && csrfRelevantStore(store) && (!entryOnly || call.Block == fn.EntryBlock) {
				writes[fn.ID] = call
				break
			}
		}
	}
	return writes
}

func csrfRelevantStore(store model.StoreAccess) bool {
	return store.Medium == "orm" || store.Medium == "session"
}

func firstStateChangingCall(fn *ir.Function, writes map[string]*ir.Call, m model.Model,
	entryOnly bool,
) *ir.Call {
	for _, call := range fn.Calls {
		if call.Block == "" || (entryOnly && call.Block != fn.EntryBlock) {
			continue
		}
		if store, ok := m.StoreWriteAt(call.Callee.Symbol, call.Method, call.ReceiverType); ok && csrfRelevantStore(store) {
			return call
		}
		ids := append([]string{call.Callee.FunctionID}, call.Callee.PossibleFunctionIDs...)
		for _, id := range ids {
			if id != "" && writes[id] != nil {
				return call
			}
		}
	}
	return nil
}

func csrfFinding(ix *ir.Index, fn *ir.Function, ep *ir.EntryPoint, trigger *ir.Call,
	exempt bool, rule model.GuardRule,
) taint.Finding {
	loc := trigger.Loc
	label := strings.ToUpper(ep.Detail["method"]) + " route"
	declaration := fmt.Sprintf("%s admits this request method", label)
	if exempt {
		label = "@csrf_exempt"
		declaration = "the entry point explicitly removes CSRF enforcement"
		if declared := csrfExemptionLoc(ep); declared.File != "" {
			loc = declared
		}
	}
	return taint.Finding{
		Analysis:      rule.ID,
		DataClass:     "request-entry",
		ChannelID:     rule.ID,
		Class:         rule.Finding,
		CWE:           rule.CWE,
		Message:       rule.Reason,
		Confidence:    taint.High,
		SourceLoc:     loc,
		SourceLabel:   label,
		EntryPoint:    taint.EntryLabel(*ep),
		EntryMethod:   ep.Detail["method"],
		EntryPath:     ep.Detail["path"],
		EntryAnchored: true,
		EntryTrust:    ep.TrustLevel(),
		SinkLoc:       loc,
		SinkFunction:  fn.Name,
		SinkSymbol:    callName(ix, trigger),
		SinkRational:  rule.Rationale,
		Path: []taint.Hop{
			{Loc: loc, Description: declaration, Resolution: ir.Resolved},
			{Loc: trigger.Loc, Description: fmt.Sprintf("unconditionally calls %s(), whose resolved call tree writes persistent state", callName(ix, trigger)), Resolution: trigger.Callee.Resolution},
		},
	}
}

func csrfExemptionLoc(ep *ir.EntryPoint) ir.Loc {
	line, lineErr := strconv.Atoi(ep.Detail["csrfExemptLine"])
	column, columnErr := strconv.Atoi(ep.Detail["csrfExemptColumn"])
	if ep.Detail["csrfExemptFile"] == "" || lineErr != nil || columnErr != nil {
		return ir.Loc{}
	}
	return ir.Loc{File: ep.Detail["csrfExemptFile"], Line: line, Column: column}
}
