package rules_test

import (
	"testing"

	"keyguard/internal/testkit"
)

// Some tests run betterleaks, so the run ends by checking that none of them changed an engine.
func TestMain(m *testing.M) { testkit.Main(m) }
