package known

import (
	"testing"

	"keyguard/internal/testkit"
)

// Learn is tested against the real betterleaks, gitleaks and trufflehog, so the engine
// binaries are hashed before and after: a test that changed one fails the run.
func TestMain(m *testing.M) { testkit.Main(m) }
