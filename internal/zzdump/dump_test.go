package zzdump

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"keyguard/internal/pattern"
	"keyguard/internal/pattern/rules"
)

// Scratch: writes every finding of a directory, one line each, for a comparison of two builds.
func TestZZDump(t *testing.T) {
	dir, out := os.Getenv("ZZ_DIR"), os.Getenv("ZZ_OUT")
	if dir == "" || out == "" {
		t.Skip()
	}
	s := pattern.New(rules.All, rules.Global, pattern.Options{Paths: pattern.PathsNative, Threads: 6})
	var lines []string
	st, err := s.ScanDir(context.Background(), dir, func(f pattern.Finding, data []byte) {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%d\t%d\t%d\t%d\t%d\t%.4f\t%s", f.Rule.ID, f.Path, f.Line, f.Base+f.MatchStart, f.Base+f.MatchEnd, f.Base+f.Start, f.Base+f.End, f.Entropy, strings.Join(f.Tags, ",")))
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	os.WriteFile(out, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	t.Logf("%d findings, %+v", len(lines), st)
}
