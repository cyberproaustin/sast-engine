package model

import "testing"

// The production allowlist stays empty because none of the measured commands lack an
// option grammar. This pins the extension point without declaring an unknown executable
// safe merely because its option surface has not been modelled yet.
func TestArgvProgramHasNoOptionsUsesExactBasenameAllowlist(t *testing.T) {
	m := Builtin()
	m.ArgvNoOptionPrograms = []string{"data-sink"}

	for _, program := range []string{"data-sink", "/opt/tools/data-sink", `C:\tools\data-sink`} {
		if !m.ArgvProgramHasNoOptions(program) {
			t.Errorf("allowlisted program %q was not recognized", program)
		}
	}
	for _, program := range []string{"unknown", "data-sink-helper", ""} {
		if m.ArgvProgramHasNoOptions(program) {
			t.Errorf("program %q matched the exact allowlist", program)
		}
	}
}
