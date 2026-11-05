package hooks

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode/utf8"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

const (
	maxRows = 25
	maxWhy  = 56
)

// writeBlock prints the block message: a table of FILE / LINE / TYPE / SECRET / WHY, then
// what to do. Short lines and a numeric column on purpose. The SECRET column is the shape
// (prefix, ellipsis, at most four trailing characters) and nothing more: this text lands
// in terminals, CI logs and agent transcripts.
func writeBlock(w io.Writer, title string, hits []core.Hit) {
	var b strings.Builder
	fmt.Fprintf(&b, "keyguard: %s: %d finding%s\n\n", title, len(hits), plural(len(hits)))

	rows := hits
	if len(rows) > maxRows {
		rows = rows[:maxRows]
	}
	withCommit := false
	lineW := len("LINE")
	for _, h := range rows {
		withCommit = withCommit || h.Loc.Commit != ""
		lineW = max(lineW, len(lineText(h.Loc.Line)))
	}

	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	head := []string{"FILE", pad("LINE", lineW), "TYPE", "SECRET", "WHY"}
	if withCommit {
		head = append([]string{"COMMIT"}, head...)
	}
	fmt.Fprintln(tw, "  "+strings.Join(head, "\t"))
	var ids []string
	for _, h := range rows {
		id := ""
		if h.FP != "" {
			id = fp.ID(h.FP)
			ids = append(ids, id)
		}
		cols := []string{
			clip(cell(h.Loc.Path, "-"), 44, true),
			pad(lineText(h.Loc.Line), lineW),
			clip(cell(firstNonEmpty(h.Type, h.Rule), "-"), 24, false),
			safeShape(h.Shape),
			why(h, id),
		}
		if withCommit {
			cols = append([]string{shortSHA(h.Loc.Commit)}, cols...)
		}
		fmt.Fprintln(tw, "  "+strings.Join(cols, "\t"))
	}
	_ = tw.Flush()
	if len(hits) > len(rows) {
		fmt.Fprintf(&b, "  ... and %d more\n", len(hits)-len(rows))
	}

	b.WriteString("\n")
	b.WriteString("  fix: move the value to a gitignored .env and read it from the environment.\n")
	b.WriteString("  do not bypass with --no-verify: real keys are also blocked at the\n")
	b.WriteString("  ref level, and GitHub is re-scanned every minute.\n")
	switch ids = dedupe(ids); len(ids) {
	case 0:
		b.WriteString("  not a secret? rename the file, or ask for it to be allowed.\n")
	case 1:
		fmt.Fprintf(&b, "  false positive? keyguard allow %s\n", ids[0])
	default:
		b.WriteString("  false positive? keyguard allow <id from the WHY column>\n")
	}
	_, _ = io.WriteString(w, b.String())
}

// why is the reason for a row. The id is what `keyguard allow` takes, so it is the one
// part that is never cut: the reason is shortened to make room for it.
func why(h core.Hit, id string) string {
	var s string
	switch {
	case h.Known != "":
		s = "your learned key"
		if f := strings.Fields(h.Known); len(f) > 1 { // "<entry id> <name>"
			s += " " + cell(strings.Join(f[1:], " "), "")
		}
	case h.Engine == "filename":
		s = cell(h.Context, "")
	default:
		s = cell(h.Rule, "-")
	}
	if h.Verified == core.Live {
		s = "verified live: " + s // first, so clipping never cuts the one fact that sets the urgency
	}
	if id == "" {
		return clip(s, maxWhy, false)
	}
	return clip(s, maxWhy-len(id)-3, false) + " (" + id + ")"
}

// pemShape is what fp.Shape returns for a PEM block: the only shape whose tail is longer
// than four characters.
const pemShape = "-----BEGIN…KEY-----"

// safeShape is the last line of defence for invariant 1. Shapes come from the engine
// normalizers, which are supposed to call fp.Shape; if one ever hands over a raw value
// instead, this keeps the output to what a shape may show: a short public prefix, an
// ellipsis, and at most four trailing characters.
func safeShape(s string) string {
	if s == "" {
		return "-"
	}
	if s == pemShape {
		return s
	}
	i := strings.LastIndex(s, "…")
	if i < 0 {
		return "…"
	}
	prefix, tail := []rune(cell(s[:i], "")), []rune(cell(s[i+len("…"):], ""))
	if len(prefix) > 16 {
		prefix = nil
	}
	if len(tail) > 4 {
		tail = tail[len(tail)-4:]
	}
	return string(prefix) + "…" + string(tail)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func lineText(n int) string {
	if n <= 0 {
		return "-"
	}
	return strconv.Itoa(n)
}

// pad right-aligns, so line numbers sit in a column.
func pad(s string, w int) string {
	if n := utf8.RuneCountInString(s); n < w {
		return strings.Repeat(" ", w-n) + s
	}
	return s
}

// cell makes any engine- or repo-supplied text safe for a terminal: control characters
// (including ESC) become '?'.
func cell(s, empty string) string {
	if s == "" {
		return empty
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

// clip shortens to n runes. For paths keepTail keeps the end, where the file name is.
func clip(s string, n int, keepTail bool) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if keepTail {
		return "…" + string(r[len(r)-(n-1):])
	}
	return string(r[:n-1]) + "…"
}

func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	if s == "" {
		return "-"
	}
	return s
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}
