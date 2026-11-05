package notify

import (
	"os/exec"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzQuote hands arbitrary text to the real AppleScript interpreter inside the string
// literal quote builds and requires the same text back. A script that returns anything
// else, or fails to compile, means the text got out of its literal.
func FuzzQuote(f *testing.F) {
	for _, s := range nasty {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		osa := realOsascript(t)
		want := text(in, 1000) // exactly what Notify would put in the literal
		out, err := exec.Command(osa, "-e", "return "+quote(want)).CombinedOutput()
		if err != nil {
			t.Fatalf("osascript rejected a quoted string: %v: %s", err, out)
		}
		if got := strings.TrimSuffix(string(out), "\n"); got != want {
			t.Fatalf("round trip changed the text: %q -> %q", want, got)
		}
		if !utf8.ValidString(want) {
			t.Fatal("text produced invalid UTF-8")
		}
	})
}
