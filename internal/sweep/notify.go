package sweep

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"keyguard/internal/core"
	"keyguard/internal/report"
)

func plainType(t string) string {
	if t == "" || t == "generic" || t == "unknown" || t == "other" || strings.HasPrefix(t, "generic-") {
		return ""
	}
	return t
}

func visWord(v core.Visibility) string {
	if v == core.SecretGist {
		return "secret gist"
	}
	return string(v)
}

// describe composes one alert. It is built from the Secret's own display fields (id, type,
// shape, locations); the final scrub is a belt over braces, since a path can be anything.
func describe(s core.Secret) (title, body string) {
	thing := "secret"
	if t := plainType(s.Type); t != "" {
		thing = t + " key"
	}
	var what string
	switch {
	case s.Known != "" && s.Exposed():
		what = "your " + thing + " is exposed"
	case s.Known != "":
		what = "your " + thing + " is in a private place"
	case s.Verified == core.Live && s.Exposed():
		what = "live " + thing + " is exposed"
	case s.Verified == core.Live:
		what = "live " + thing + " in a private place"
	default:
		what = thing
	}
	lead := "keyguard " + strings.ToUpper(s.Severity.String())
	if s.Notified > core.None {
		lead = "keyguard ESCALATED to " + strings.ToUpper(s.Severity.String())
	}
	title = lead + ": " + what

	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n", s.ID, s.Shape)
	switch {
	case s.Known != "":
		if _, name, ok := strings.Cut(s.Known, " "); ok {
			fmt.Fprintf(&b, "learned from this Mac (%s)\n", name)
		} else {
			b.WriteString("learned from this Mac\n")
		}
	case s.Verified == core.Live:
		b.WriteString("the provider confirmed it works\n")
	}
	locs := slices.Clone(s.Locations)
	slices.SortStableFunc(locs, func(a, c core.Location) int { // places a stranger can read come first
		switch {
		case a.Visibility.Exposed() && !c.Visibility.Exposed():
			return -1
		case !a.Visibility.Exposed() && c.Visibility.Exposed():
			return 1
		}
		return cmp.Compare(a.Source+a.Path, c.Source+c.Path)
	})
	for i, l := range locs {
		if i == 2 {
			fmt.Fprintf(&b, "+%d more place(s)\n", len(locs)-2)
			break
		}
		where := l.Source
		if l.Path != "" {
			where += "  " + l.Path
			if l.Line > 0 {
				where += fmt.Sprintf(":%d", l.Line)
			}
		}
		fmt.Fprintf(&b, "%s (%s)\n", where, visWord(l.Visibility))
	}
	b.WriteString("Rotate it, then open the report.")
	return title, maskLines(b.String())
}

// describeDigest is the one notification that stands in for the alerts beyond the per-run
// limit. Its severity is the highest of them, so a critical one still reaches iMessage.
func describeDigest(list []core.Secret) (title, body string, sev core.Severity) {
	sorted := slices.Clone(list)
	slices.SortStableFunc(sorted, func(a, b core.Secret) int {
		if a.Severity != b.Severity {
			return int(b.Severity) - int(a.Severity)
		}
		return cmp.Compare(a.ID, b.ID)
	})
	sev = sorted[0].Severity
	title = fmt.Sprintf("keyguard %s: %d more keys need attention", strings.ToUpper(sev.String()), len(sorted))
	var b strings.Builder
	for i, s := range sorted {
		if i == 8 {
			fmt.Fprintf(&b, "+%d more; open the report\n", len(sorted)-8)
			break
		}
		label := plainType(s.Type)
		if label == "" {
			label = "secret"
		}
		fmt.Fprintf(&b, "%s  %s  %s  %s\n", s.ID, label, s.Shape, s.Severity)
	}
	b.WriteString("Rotate the critical ones first.")
	return title, maskLines(b.String()), sev
}

// maskLines is the last guard on an alert's text. It uses the report's masking, not fp.Scrub:
// Scrub treats a name like github.com/hangryclaude/shop-factory-2026-11-final as one long
// random-looking token and replaces it, which left a critical alert that did not say which
// repo. The report's mask keeps names, paths and URLs readable and still removes anything
// shaped like a key. It works a line at a time, as the notifier does.
func maskLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = report.Mask(l)
	}
	return strings.Join(lines, "\n")
}
