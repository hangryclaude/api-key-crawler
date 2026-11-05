package rules

import (
	"testing"

	"keyguard/internal/testkit"
)

// The tests run betterleaks, so the run ends by checking that none of them changed an engine.
func TestMain(m *testing.M) { testkit.Main(m) }
