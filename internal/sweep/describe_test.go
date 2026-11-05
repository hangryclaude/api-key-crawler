package sweep

import (
	"strings"
	"testing"

	"keyguard/internal/core"
)

func TestAlertNamesTheRepoEvenWhenItsNameIsLong(t *testing.T) {
	s := core.Secret{
		ID: "kg1a2b3c", Type: "openai", Shape: "sk-…abcd", Known: "kg1a2b3c OPENAI_API_KEY", Severity: core.Critical,
		Locations: []core.Location{{
			Source: "github.com/hangryclaude/shop-factory-2026-11-final", Path: "src/app/config.py", Line: 12, Visibility: core.Public,
		}},
	}
	title, body := describe(s)
	if !strings.Contains(body, "github.com/hangryclaude/shop-factory-2026-11-final") {
		t.Fatalf("a critical alert that does not say which repo is not much of an alert:\n%s", body)
	}
	if !strings.Contains(body, "src/app/config.py:12") || !strings.Contains(title, "CRITICAL") {
		t.Errorf("title %q body %q", title, body)
	}
	if lines := strings.Split(body, "\n"); len(lines) < 4 {
		t.Errorf("the alert is several lines and masking must not flatten it: %q", body)
	}
}

func TestAlertNeverCarriesAKeyShapedToken(t *testing.T) {
	leaky := "sk-" + fakeKey(t, "", 48) // a path or source name is attacker-controlled text
	s := core.Secret{
		ID: "kg1a2b3c", Type: "openai", Shape: "sk-…abcd", Severity: core.High, Verified: core.Live,
		Locations: []core.Location{{Source: "github.com/o/r", Path: "dir/" + leaky + ".env", Line: 3, Visibility: core.Public}},
	}
	_, body := describe(s)
	if strings.Contains(body, leaky) || strings.Contains(body, leaky[3:]) {
		t.Fatalf("the alert carries a key-shaped token from a path:\n%s", body)
	}
	_, digestBody, _ := describeDigest([]core.Secret{s, s})
	if strings.Contains(digestBody, leaky) {
		t.Fatalf("the digest carries one:\n%s", digestBody)
	}
}
