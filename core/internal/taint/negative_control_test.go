package taint_test

import (
	"os"
	"strings"
	"testing"

	"github.com/cyberproaustin/sast-engine/core/internal/ir"
	"github.com/cyberproaustin/sast-engine/core/internal/model"
	"github.com/cyberproaustin/sast-engine/core/internal/scan"
)

// Negative controls.
//
// A corpus scoring precision 1.00 proves the engine did not report the safe routes. It
// does NOT prove the engine looked at them: an analysis that silently failed to lower the
// file, or a channel whose symbol was misspelled, scores exactly the same. Every zero in
// this project is supposed to be earned, and the only way to show that is to break the
// discriminator on purpose and watch the finding appear.
//
// Each test below removes ONE condition from the model and asserts that a route the
// fixture calls safe becomes a finding. If a test here stops failing-open -- if the
// finding does not appear when the condition is removed -- the corresponding 1.00 has
// stopped meaning anything and the corpus needs looking at.

func runWith(t *testing.T, corpus string, mutate func(*model.Model)) []string {
	t.Helper()

	f, err := os.Open("testdata/" + corpus + ".ir.json")
	if err != nil {
		t.Fatalf("open corpus IR: %v", err)
	}
	defer f.Close()

	doc, err := ir.Load(f)
	if err != nil {
		t.Fatalf("load corpus IR: %v", err)
	}

	m := model.Builtin()
	mutate(&m)

	var out []string
	for _, fnd := range scan.Run(doc, m, nil).Taint.Findings {
		out = append(out, fnd.CWE+" "+fnd.SinkLoc.String())
	}
	return out
}

func countCWE(findings []string, cwe string) int {
	n := 0
	for _, f := range findings {
		if strings.HasPrefix(f, cwe+" ") {
			n++
		}
	}
	return n
}

// The unsalted-hash channel stays quiet on a salted password because it requires the
// WHOLE value. Remove that and the salted route reports, which is what shows the silence
// came from the requirement rather than from the channel never matching.
func TestSaltedPasswordIsSilentBecauseOfTheWholeValueRequirement(t *testing.T) {
	before := countCWE(runWith(t, "express-unsalted-hash", func(m *model.Model) {}), "CWE-759")
	after := countCWE(runWith(t, "express-unsalted-hash", func(m *model.Model) {
		for i := range m.Channels {
			if m.Channels[i].ID == "unsalted-hash" {
				m.Channels[i].RequiresWholeValue = false
			}
		}
	}), "CWE-759")
	if after <= before {
		t.Errorf("removing the whole-value requirement produced %d findings, not more than the %d with it; "+
			"the salted route is silent for some reason other than the requirement", after, before)
	}
}

// The cookie-lifetime rule stays quiet on a year-long THEME cookie because it asks what
// the cookie carries. Remove the name qualifier and the theme cookie reports.
func TestThemeCookieIsSilentBecauseOfTheNameQualifier(t *testing.T) {
	before := countCWE(runWith(t, "express-session-lifetime", func(m *model.Model) {}), "CWE-613")
	after := countCWE(runWith(t, "express-session-lifetime", func(m *model.Model) {
		for i := range m.CallShapes {
			if m.CallShapes[i].ID == "long-lived-session" {
				m.CallShapes[i].Qualifiers = nil
			}
		}
	}), "CWE-613")
	if after <= before {
		t.Errorf("removing the cookie-name qualifier produced %d findings, not more than the %d with it; "+
			"the theme cookie is silent for some reason other than the qualifier", after, before)
	}
}

// The password-policy rule stays quiet on a twelve-character minimum because of the
// threshold. Raise it and the strict route reports.
func TestStrictPasswordPolicyIsSilentBecauseOfTheThreshold(t *testing.T) {
	before := countCWE(runWith(t, "express-password-policy", func(m *model.Model) {}), "CWE-521")
	after := countCWE(runWith(t, "express-password-policy", func(m *model.Model) {
		for i := range m.Decisions {
			if m.Decisions[i].ID == "weak-password-policy" {
				high := 32
				m.Decisions[i].OtherBelow = &high
			}
		}
	}), "CWE-521")
	if after <= before {
		t.Errorf("raising the length threshold produced %d findings, not more than the %d below it; "+
			"the twelve-character route is silent for some reason other than the number", after, before)
	}
}

// The bind-address rule stays quiet on a loopback address because of the value it forbids.
// Add loopback to that list and the local route reports.
func TestLoopbackBindIsSilentBecauseOfTheAddressList(t *testing.T) {
	before := countCWE(runWith(t, "express-bind-address", func(m *model.Model) {}), "CWE-1327")
	after := countCWE(runWith(t, "express-bind-address", func(m *model.Model) {
		for i := range m.CallShapes {
			if m.CallShapes[i].ID == "bound-to-every-interface" {
				m.CallShapes[i].Disallowed = append(m.CallShapes[i].Disallowed, "127.0.0.1")
			}
		}
	}), "CWE-1327")
	if after <= before {
		t.Errorf("adding the loopback address produced %d findings, not more than the %d without it; "+
			"the loopback route is silent for some reason other than the address list", after, before)
	}
}

// The template rule stays quiet on an ESCAPED interpolation because the frontend read the
// view and recorded which ones the engine escapes. Make the escaped channel
// indistinguishable from the unescaped one and those lines report -- which is what shows
// the silence came from reading the template rather than from never opening it.
func TestEscapedInterpolationIsSilentBecauseTheTemplateWasRead(t *testing.T) {
	before := countCWE(runWith(t, "express-template-xss", func(m *model.Model) {}), "CWE-79")
	after := countCWE(runWith(t, "express-template-xss", func(m *model.Model) {
		for i := range m.Channels {
			if m.Channels[i].ID == "template-output" {
				m.Channels[i].Context = "html"
				m.Channels[i].CWE = "CWE-79"
			}
		}
	}), "CWE-79")
	if after <= before {
		t.Errorf("treating escaped output as markup produced %d findings, not more than the %d with the distinction; "+
			"the escaped interpolation is silent for some reason other than being escaped", after, before)
	}
}
