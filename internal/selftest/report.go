package selftest

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Group is one section of the report, folded into a single line for the record the doctor
// reads: the doctor wants to know which part of the gates broke, not 33 rows.
type Group struct {
	ID      string  `json:"id"`
	Title   string  `json:"title"`
	OK      bool    `json:"ok"`
	Checks  int     `json:"checks"`
	Detail  string  `json:"detail"`
	Seconds float64 `json:"seconds"`
}

// Groups folds the checks that ran into their groups, in report order.
func (r *Report) Groups() []Group {
	var out []Group
	for _, g := range groups {
		grp := Group{ID: g.id, Title: g.title, OK: true}
		var failed []string
		for _, c := range r.Checks {
			if c.Group != g.id {
				continue
			}
			grp.Checks++
			grp.Seconds += c.Seconds
			if !c.OK {
				grp.OK = false
				failed = append(failed, c.ID+" ("+c.Detail+")")
			}
		}
		if grp.Checks == 0 {
			continue
		}
		switch {
		case !grp.OK:
			grp.Detail = "FAILED " + strings.Join(failed, "; ")
			if rs := []rune(grp.Detail); len(rs) > 240 {
				grp.Detail = string(rs[:239]) + "…"
			}
		case g.id == "speed":
			var parts []string
			for _, l := range r.Latency {
				parts = append(parts, fmt.Sprintf("%s p50 %s of %s", l.Hook, fmtMs(l.P50ms), fmtMs(l.BudgetMs)))
			}
			grp.Detail = strings.Join(parts, ", ")
		default:
			grp.Detail = fmt.Sprintf("%d %s passed", grp.Checks, map[bool]string{true: "check", false: "checks"}[grp.Checks == 1])
		}
		out = append(out, grp)
	}
	return out
}

// Table writes the report as a table: a heading per group, then one row per check with its
// time in a column of its own so the numbers line up.
func (r *Report) Table(w io.Writer) {
	fmt.Fprintf(w, "git gates: the hooks of %s, on a throwaway machine (git %s)\n", r.Binary, r.Git)
	width := 0
	for _, c := range r.Checks {
		width = max(width, utf8.RuneCountInString(c.Name))
	}
	title := map[string]string{}
	for _, g := range groups {
		title[g.id] = g.title
	}
	last := ""
	for _, c := range r.Checks {
		if c.Group != last {
			last = c.Group
			fmt.Fprintf(w, "\n%s\n", title[c.Group])
		}
		mark := "ok  "
		if !c.OK {
			mark = "FAIL"
		}
		name := c.Name + strings.Repeat(" ", width-utf8.RuneCountInString(c.Name))
		fmt.Fprintf(w, "  %s  %s  %7s  %s\n", mark, name, fmt.Sprintf("%.2f s", c.Seconds), c.Detail)
	}
	if r.Machine != "" {
		fmt.Fprintf(w, "\nthe throwaway machine is kept at %s\n", r.Machine)
	}
	failed := r.Failed()
	if len(failed) == 0 {
		fmt.Fprintf(w, "\n%d of %d checks passed (%.1f s)\n", len(r.Checks), len(r.Checks), r.Seconds)
		return
	}
	ids := make([]string, len(failed))
	for i, c := range failed {
		ids[i] = c.ID
	}
	fmt.Fprintf(w, "\n%d of %d checks FAILED: %s (%.1f s)\n", len(failed), len(r.Checks), strings.Join(ids, ", "), r.Seconds)
	fmt.Fprintf(w, "run one again with: keyguard selftest --only %s\n", ids[0])
}
