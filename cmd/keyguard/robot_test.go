package main

import (
	"encoding/json"
	"strings"
	"testing"

	"keyguard/internal/install"
)

// The doctor's agent-facing surface: one call that says what is wrong and what to run, a
// capabilities document that matches the code, and a handbook. All data on stdout, all of it
// free of anything but ids, paths, versions and commands.

func TestDoctorRobotTriage(t *testing.T) {
	m := newMachine(t)
	r := m.kg("doctor", "--robot-triage", "--quick")
	if r.code != exitFound {
		t.Fatalf("an empty machine is not healthy: exit %d\n%s", r.code, r.out)
	}
	var tr struct {
		SchemaVersion int  `json:"schema_version"`
		Healthy       bool `json:"healthy"`
		Summary       string
		Findings      []struct{ ID, Status, Fix string }
		Actions       []string `json:"actions_planned"`
		NeedsUser     []string `json:"needs_user"`
		Recommended   string   `json:"recommended_command"`
		Capabilities  string   `json:"capabilities_command"`
	}
	if err := json.Unmarshal([]byte(r.out), &tr); err != nil {
		t.Fatalf("not JSON on stdout: %v\n%s", err, r.out)
	}
	if tr.SchemaVersion != install.DoctorSchemaVersion || tr.Healthy || !strings.Contains(tr.Summary, "failing") || len(tr.Findings) == 0 {
		t.Errorf("triage header: %+v", tr)
	}
	if tr.Recommended != "keyguard install" || tr.Capabilities != "keyguard doctor capabilities" {
		t.Errorf("recommended %q, capabilities %q", tr.Recommended, tr.Capabilities)
	}
	if len(tr.NeedsUser) != 1 || !strings.HasPrefix(tr.NeedsUser[0], "! f=") {
		t.Errorf("the guard registration belongs to the user: %v", tr.NeedsUser)
	}
	for _, a := range tr.Actions {
		if strings.HasPrefix(a, "! ") {
			t.Errorf("an action an agent may run starts with a bang: %q", a)
		}
	}
	// stdout is the data and nothing else: one JSON document.
	dec := json.NewDecoder(strings.NewReader(r.out))
	var first, second any
	if err := dec.Decode(&first); err != nil || dec.Decode(&second) == nil {
		t.Errorf("stdout is not exactly one JSON document")
	}

	// --robot is --json under the name agents guess first.
	a := m.kg("doctor", "--robot", "--quick")
	b := m.kg("doctor", "--json", "--quick")
	if a.code != exitFound || b.code != exitFound {
		t.Fatalf("exits %d %d", a.code, b.code)
	}
	var ra, rb struct {
		SchemaVersion int `json:"schema_version"`
		Checks        []struct{ ID, Status string }
	}
	if json.Unmarshal([]byte(a.out), &ra) != nil || json.Unmarshal([]byte(b.out), &rb) != nil || ra.SchemaVersion != 1 || len(ra.Checks) != len(rb.Checks) || len(ra.Checks) == 0 {
		t.Errorf("--robot and --json disagree:\n%s\n%s", a.out, b.out)
	}

	// After install the same call has less to say, and it is still valid JSON.
	m.install()
	r = m.kg("doctor", "--robot-triage", "--quick")
	var after struct {
		Findings []struct{ ID string }
	}
	if err := json.Unmarshal([]byte(r.out), &after); err != nil {
		t.Fatal(err)
	}
	for _, f := range after.Findings {
		if strings.HasPrefix(f.ID, "hooks.") {
			t.Errorf("hooks are installed, yet the triage still lists %s", f.ID)
		}
	}
}

func TestDoctorCapabilitiesMatchTheCode(t *testing.T) {
	m := newMachine(t)
	r := m.kg("doctor", "capabilities")
	if r.code != 0 {
		t.Fatalf("capabilities: %d\n%s", r.code, r.out)
	}
	var caps struct {
		Tool          string `json:"tool"`
		Version       string `json:"version"`
		SchemaVersion int    `json:"schema_version"`
		ReadOnly      bool   `json:"read_only"`
		Commands      []string
		ExitCodes     map[string]string `json:"exit_codes"`
		Detectors     []install.CheckInfo
		Fixers        []string
		Layers        []string
	}
	if err := json.Unmarshal([]byte(r.out), &caps); err != nil {
		t.Fatalf("%v\n%s", err, r.out)
	}
	if caps.Tool != "keyguard" || caps.Version != version || caps.SchemaVersion != install.DoctorSchemaVersion || !caps.ReadOnly {
		t.Errorf("header: %+v", caps)
	}
	// What the document says the doctor looks at is what the doctor looks at.
	want := install.Catalog()
	if len(caps.Detectors) != len(want) {
		t.Fatalf("capabilities lists %d detectors, the catalog has %d", len(caps.Detectors), len(want))
	}
	ran := map[string]bool{}
	var rep struct {
		Checks []struct{ ID string }
	}
	if err := json.Unmarshal([]byte(m.kg("doctor", "--json").out), &rep); err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Checks {
		ran[c.ID] = true
	}
	for _, d := range caps.Detectors {
		if !ran[d.ID] && !d.Optional {
			t.Errorf("capabilities promises %s, and a full run does not produce it", d.ID)
		}
	}
	for id := range ran {
		listed := false
		for _, d := range caps.Detectors {
			listed = listed || d.ID == id
		}
		if !listed {
			t.Errorf("the doctor produced %s and capabilities does not list it", id)
		}
	}
	for _, c := range []string{"0", "1", "2", "3"} {
		if caps.ExitCodes[c] == "" {
			t.Errorf("exit code %s is not documented", c)
		}
	}
	for _, cmd := range []string{"doctor --robot-triage", "doctor health", "doctor capabilities", "doctor robot-docs"} {
		found := false
		for _, have := range caps.Commands {
			found = found || have == cmd
		}
		if !found {
			t.Errorf("capabilities does not list the command %q", cmd)
		}
	}
	if len(caps.Fixers) == 0 || len(caps.Layers) < 8 {
		t.Errorf("fixers %v layers %v", caps.Fixers, caps.Layers)
	}
	// Every command it lists really exists: the handbook mentions the same ones.
	hb := m.kg("doctor", "robot-docs")
	for _, s := range []string{"--robot-triage", "--json", "health", "--explain", "capabilities", "needs_user", "refused to you"} {
		if !strings.Contains(hb.out, s) {
			t.Errorf("the handbook does not mention %q", s)
		}
	}
	if hb.code != 0 {
		t.Errorf("robot-docs exit %d", hb.code)
	}
}
