package install

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strings"

	"keyguard/internal/core"
)

// The jobs PLAN.md layer 4 names, and the weekly engine check beside them.
const (
	LabelPoll    = "io.github.hangryclaude.keyguard.poll"
	LabelDeep    = "io.github.hangryclaude.keyguard.deep"
	LabelUpgrade = "io.github.hangryclaude.keyguard.upgrade"

	// PollSeconds is how often the poll runs. The inventory asks GitHub with conditional
	// requests, so an idle poll is a handful of 304s that cost no quota and about a second
	// (measured: 945 ms for hangryclaude, 1.3 s for alt-builds), and a minute bounds how long a
	// leak can sit before it is seen. GitHub itself asks for no faster than X-Poll-Interval.
	PollSeconds = 60
)

// job is one launchd agent.
type job struct {
	label    string
	args     []string // after the binary
	interval int      // StartInterval seconds; 0 when calendar is used
	calendar map[string]int
}

func jobsFor() []job {
	return []job{
		{label: LabelPoll, args: []string{"poll"}, interval: PollSeconds},
		// Sunday 03:30, when nothing else on this Mac is awake to compete for the cores.
		{label: LabelDeep, args: []string{"deep"}, calendar: map[string]int{"Weekday": 0, "Hour": 3, "Minute": 30}},
		// Saturday 04:00, a day away from the deep scan: it downloads engines and runs the bench
		// on them, which is CPU the scan should not have to share. It only decides and writes
		// the decision down; switching an engine is `keyguard engines check-upgrade --apply`.
		{label: LabelUpgrade, args: []string{"engines", "check-upgrade"}, calendar: map[string]int{"Weekday": 6, "Hour": 4, "Minute": 0}},
	}
}

func (j job) file(dir string) string { return filepath.Join(dir, j.label+".plist") }

// agentPath is the PATH the jobs run with: launchd's own is /usr/bin:/bin:/usr/sbin:/sbin,
// which finds neither gh nor the engines.
func agentPath(home string) string {
	return strings.Join([]string{"/opt/homebrew/bin", filepath.Join(home, ".local", "bin"), "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"}, ":")
}

// plist renders the job. Logs go to <root>/logs, which holds counts and ids only.
func (j job) plist(bin, home string, p core.Paths) []byte {
	var b bytes.Buffer
	s := func(v string) string {
		var e bytes.Buffer
		_ = xml.EscapeText(&e, []byte(v))
		return "<string>" + e.String() + "</string>"
	}
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	fmt.Fprintf(&b, "\t<key>Label</key>\n\t%s\n", s(j.label))
	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	fmt.Fprintf(&b, "\t\t%s\n", s(bin))
	for _, a := range j.args {
		fmt.Fprintf(&b, "\t\t%s\n", s(a))
	}
	b.WriteString("\t</array>\n")
	if j.interval > 0 {
		fmt.Fprintf(&b, "\t<key>StartInterval</key>\n\t<integer>%d</integer>\n", j.interval)
	}
	if len(j.calendar) > 0 {
		b.WriteString("\t<key>StartCalendarInterval</key>\n\t<dict>\n")
		for _, k := range []string{"Weekday", "Hour", "Minute"} {
			if v, ok := j.calendar[k]; ok {
				fmt.Fprintf(&b, "\t\t<key>%s</key>\n\t\t<integer>%d</integer>\n", k, v)
			}
		}
		b.WriteString("\t</dict>\n")
	}
	b.WriteString("\t<key>EnvironmentVariables</key>\n\t<dict>\n")
	fmt.Fprintf(&b, "\t\t<key>PATH</key>\n\t\t%s\n", s(agentPath(home)))
	if p.Root != filepath.Join(home, ".keyguard") {
		// A root that is not ~/.keyguard (a test, a selftest) has to be told to the job.
		fmt.Fprintf(&b, "\t\t<key>KEYGUARD_HOME</key>\n\t\t%s\n", s(p.Root))
	}
	b.WriteString("\t</dict>\n")
	fmt.Fprintf(&b, "\t<key>StandardOutPath</key>\n\t%s\n", s(filepath.Join(p.Logs, strings.TrimPrefix(j.label, "io.github.hangryclaude.keyguard.")+".log")))
	fmt.Fprintf(&b, "\t<key>StandardErrorPath</key>\n\t%s\n", s(filepath.Join(p.Logs, strings.TrimPrefix(j.label, "io.github.hangryclaude.keyguard.")+".err.log")))
	b.WriteString("\t<key>Nice</key>\n\t<integer>5</integer>\n")
	b.WriteString("\t<key>LowPriorityIO</key>\n\t<true/>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes()
}
