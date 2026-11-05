package sweep

import (
	"testing"

	"keyguard/internal/testkit"
)

// The real-scanner test runs betterleaks and gitleaks, so the engine binaries are hashed
// before and after: a test that changed one fails the run.
func TestMain(m *testing.M) { testkit.Main(m) }
